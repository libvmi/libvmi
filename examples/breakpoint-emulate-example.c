/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Mathieu Tarral (mathieu.tarral@ssi.gouv.fr)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This example sets a software breakpoint on a given symbol, and when the callback is called,
 * it requests to emulate a given opcode, read before placing the breakpoint,
 * which is significantly faster than singlestepping
 *
 * You have to specify the opcode size.
 *
 * For example for NtOpenFile on a Windows 7, the opcode size is 3
 *
 * [0x1403690dc]> pd 10
            ;-- ntoskrnl.exe_NtOpenFile:
            ;-- pdb.NtOpenFile:
            0x1403690dc      4c8bdc         mov r11, rsp
            0x1403690df      4881ec880000.  sub rsp, 0x88
            0x1403690e6      8b8424b80000.  mov eax, dword
            0x1403690ed      4533d2         xor r10d, r10d

 * In this case, 0x4c8bdc will be the opcode to be emulated.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

struct cb_data {
    char *symbol;
    addr_t vaddr;
    emul_insn_t emul;
};

event_response_t int3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi;
    struct cb_data *data = NULL;
    event_response_t rsp = VMI_EVENT_RESPONSE_NONE;
    if (!event->data) {
        fprintf(stderr, "No callback data !\n");
        event->interrupt_event.reinject = 1;
        return rsp;
    }
    data = (struct cb_data*)event->data;
    printf("Int 3 happened: GFN=%"PRIx64" RIP=%"PRIx64" Length: %"PRIu32"\n",
           event->interrupt_event.gfn, event->interrupt_event.gla,
           event->interrupt_event.insn_length);

    // set default behavior: reinject
    event->interrupt_event.reinject = 1;

    if (data->vaddr == event->interrupt_event.gla) {
        // our breakpoint !
        printf("We hit our breakpoint on %s, setting emulation buffer to 0x%"PRIx64"\n",
               data->symbol, *(uint64_t*)data->emul.data);
        // don't reinject
        event->interrupt_event.reinject = 0;
        // set previous opcode for emulation
        event->emul_insn = &data->emul;
        // set response to emulate instruction
        rsp |= VMI_EVENT_RESPONSE_SET_EMUL_INSN;
    }

    /*
     * By default int3 instructions have length of 1 byte unless
     * there are prefixes attached. As adding prefixes to int3 have
     * no effect, under normal circumstances no legitimate compiler/debugger
     * would add any. However, a malicious guest could add prefixes to change
     * the instruction length. Older Xen versions (prior to 4.8) don't include this
     * information and thus this length is reported as 0. In those cases the length
     * have to be established manually, or assume a non-malicious guest as we do here.
     */
    if ( !event->interrupt_event.insn_length )
        event->interrupt_event.insn_length = 1;

    return rsp;
}

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    vmi_event_t interrupt_event = {0};
    struct sigaction act = {0};
    struct cb_data data = {0};
    int opcode_size = 0;
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;

    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    char *name = NULL;

    if (argc < 4) {
        fprintf(stderr, "Usage: %s <name of VM> <symbol> <opcode size> [<socket>]\n", argv[0]);
        return retcode;
    }

    // Arg 1 is the VM name.
    name = argv[1];
    data.symbol = argv[2];
    opcode_size = atoi(argv[3]);

    if (argc == 5) {
        char *path = argv[4];

        // fill init_data
        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    // Initialize the libvmi library.
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data,
                              VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }

    printf("LibVMI init succeeded!\n");

    // pause
    if (VMI_FAILURE == vmi_pause_vm(vmi)) {
        fprintf(stderr, "Failed to pause vm\n");
        goto error_exit;
    }

    // translate symbol to paddr
    addr_t vaddr, paddr;
    if (VMI_FAILURE == vmi_translate_ksym2v(vmi, data.symbol, &vaddr)) {
        fprintf(stderr, "Fail to translate symbol %s\n", data.symbol);
        goto error_exit;
    }
    if (VMI_FAILURE == vmi_translate_kv2p(vmi, vaddr, &paddr)) {
        fprintf(stderr, "Fail to virtual address %lx\n", vaddr);
        goto error_exit;
    }

    data.vaddr = vaddr;

    // read previous opcode
    if (VMI_FAILURE == vmi_read_va(vmi, vaddr, 0, opcode_size, &data.emul.data, NULL)) {
        fprintf(stderr, "Failed to read opcode\n");
        goto error_exit;
    }
    data.emul.dont_free = 1;

    // write breakpoint
    uint8_t bp = 0xCC;
    if (VMI_FAILURE == vmi_write_8_pa(vmi, paddr, &bp)) {
        fprintf(stderr, "Failed to write breakpoint\n");
        goto error_exit;
    }
    printf("Symbol: %s, vaddr: %lx, paddr: %lx, opcode: 0x%"PRIx64"\n",
           data.symbol, vaddr, paddr, *(uint64_t*)data.emul.data);
    /* Register event to track INT3 interrupts */
    SETUP_INTERRUPT_EVENT(&interrupt_event, int3_cb);
    interrupt_event.data = &data;

    if (VMI_FAILURE == vmi_register_event(vmi, &interrupt_event)) {
        fprintf(stderr, "Failed to register event\n");
        goto error_exit;
    }

    // resume
    if (VMI_FAILURE == vmi_resume_vm(vmi)) {
        fprintf(stderr, "Failed to continue VM\n");
        goto error_exit;
    }
    printf("Waiting for events...\n");
    while (!interrupted) {
        if (VMI_FAILURE == vmi_events_listen(vmi,500)) {
            fprintf(stderr, "Failed to listen on VMI events\n");
            goto error_exit;
        }
    }
    printf("Finished with test.\n");

    retcode = 0;
error_exit:
    // restore opcode
    if (data.emul.data[0])
        vmi_write_va(vmi, vaddr, 0, opcode_size, &data.emul.data, NULL);
    vmi_resume_vm(vmi);
    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}

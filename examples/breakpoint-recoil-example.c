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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

char BREAKPOINT = 0xcc;

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

struct bp_cb_data {
    char *symbol;
    addr_t sym_vaddr;
    char saved_opcode;
    uint64_t hit_count;
};

event_response_t breakpoint_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi;
    if (!event->data) {
        fprintf(stderr, "Empty event data in breakpoint callback !\n");
        interrupted = true;
        return VMI_EVENT_RESPONSE_NONE;
    }
    // get back callback data struct
    struct bp_cb_data *cb_data = (struct bp_cb_data*)event->data;

    // default reinjection behavior
    event->interrupt_event.reinject = 1;
    // printf("INT3 event: GFN=%"PRIx64" RIP=%"PRIx64" Length: %"PRIu32"\n",
    //        event->interrupt_event.gfn, event->interrupt_event.gla,
    //        event->interrupt_event.insn_length);

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

    if (event->x86_regs->rip != cb_data->sym_vaddr) {
        // not our breakpoint
        printf("Not our breakpoint. Reinjecting INT3\n");
        return VMI_EVENT_RESPONSE_NONE;
    } else {
        // our breakpoint
        // do not reinject
        event->interrupt_event.reinject = 0;
        printf("[%"PRIu32"] Breakpoint hit at %s. Count: %"PRIu64"\n", event->vcpu_id, cb_data->symbol, cb_data->hit_count);
        cb_data->hit_count++;
        // recoil
        // write saved opcode
        if (VMI_FAILURE == vmi_write_va(vmi, event->x86_regs->rip, 0, sizeof(BREAKPOINT), &cb_data->saved_opcode, NULL)) {
            fprintf(stderr, "Failed to write back original opcode at 0x%" PRIx64 "\n", event->x86_regs->rip);
            interrupted = true;
            return VMI_EVENT_RESPONSE_NONE;
        }
        // enable singlestep
        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }
}

event_response_t single_step_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi;

    if (!event->data) {
        fprintf(stderr, "Empty event data in singlestep callback !\n");
        interrupted = true;
        return VMI_EVENT_RESPONSE_NONE;
    }

    // get back callback data struct
    struct bp_cb_data *cb_data = (struct bp_cb_data*)event->data;

    // printf("Single-step event: VCPU:%u  GFN %"PRIx64" GLA %016"PRIx64"\n",
    //        event->vcpu_id,
    //        event->ss_event.gfn,
    //        event->ss_event.gla);

    // restore breakpoint
    if (VMI_FAILURE == vmi_write_va(vmi, cb_data->sym_vaddr, 0, sizeof(BREAKPOINT), &BREAKPOINT, NULL)) {
        fprintf(stderr, "Failed to write breakpoint at 0x%" PRIx64 "\n",event->x86_regs->rip);
        interrupted = true;
        return VMI_EVENT_RESPONSE_NONE;
    }

    // disable singlestep
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

int main (int argc, char **argv)
{
    struct sigaction act = {0};
    vmi_instance_t vmi = {0};
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;
    char saved_opcode = 0;

    char *name = NULL;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <name of VM> <symbol> [<socket>]\n", argv[0]);
        return retcode;
    }

    name = argv[1];
    char *symbol = argv[2];

    // KVMi socket ?
    if (argc == 4) {
        char *path = argv[3];

        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    // init complete since we need symbols translation
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data,
                              VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        goto error_exit;
    }

    printf("LibVMI init succeeded!\n");

    // translate symbol
    addr_t sym_vaddr = 0;
    if (VMI_FAILURE == vmi_translate_ksym2v(vmi, symbol, &sym_vaddr)) {
        fprintf(stderr, "Failed to translate symbol %s\n", symbol);
        goto error_exit;
    }
    printf("Symbol %s translated to virtual address: 0x%" PRIx64 "\n", symbol, sym_vaddr);

    // pause VM
    printf("Pause VM\n");
    if (VMI_FAILURE == vmi_pause_vm(vmi)) {
        fprintf(stderr, "Failed to pause VM\n");
        goto error_exit;
    }

    // save opcode
    printf("Save opcode\n");
    if (VMI_FAILURE == vmi_read_va(vmi, sym_vaddr, 0, sizeof(BREAKPOINT), &saved_opcode, NULL)) {
        fprintf(stderr, "Failed to read opcode\n");
        goto error_exit;
    }

    // write breakpoint
    printf("Write breakpoint at 0x%" PRIx64 "\n", sym_vaddr);
    if (VMI_FAILURE == vmi_write_va(vmi, sym_vaddr, 0, sizeof(BREAKPOINT), &BREAKPOINT, NULL)) {
        fprintf(stderr, "Failed to write breakpoint\n");
        goto error_exit;
    }

    // register int3 event
    vmi_event_t int_event;
    memset(&int_event, 0, sizeof(vmi_event_t));
    int_event.version = VMI_EVENTS_VERSION;
    int_event.type = VMI_EVENT_INTERRUPT;
    int_event.interrupt_event.intr = INT3;
    int_event.callback = breakpoint_cb;

    // fill and pass struct bp_cb_data
    struct bp_cb_data cb_data = {
        .symbol = symbol,
        .sym_vaddr = sym_vaddr,
        .saved_opcode = saved_opcode,
        .hit_count = 0,
    };
    int_event.data = (void*)&cb_data;

    printf("Register interrupt event\n");
    if (VMI_FAILURE == vmi_register_event(vmi, &int_event)) {
        fprintf(stderr, "Failed to register interrupt event\n");
        goto error_exit;
    }

    // get number of vcpus
    unsigned int num_vcpus = vmi_get_num_vcpus(vmi);

    // register singlestep event
    // disabled by default
    vmi_event_t sstep_event = {0};
    sstep_event.version = VMI_EVENTS_VERSION;
    sstep_event.type = VMI_EVENT_SINGLESTEP;
    sstep_event.callback = single_step_cb;
    sstep_event.ss_event.enable = false;
    // allow singlestep on all VCPUs
    for (unsigned int vcpu=0; vcpu < num_vcpus; vcpu++)
        SET_VCPU_SINGLESTEP(sstep_event.ss_event, vcpu);
    // pass struct bp_cb_data
    sstep_event.data = (void*)&cb_data;

    printf("Register singlestep event\n");
    if (VMI_FAILURE == vmi_register_event(vmi, &sstep_event)) {
        fprintf(stderr, "Failed to register singlestep event\n");
        goto error_exit;
    }

    // resume VM
    printf("Resume VM\n");
    if (VMI_FAILURE == vmi_resume_vm(vmi)) {
        fprintf(stderr, "Failed to resume VM\n");
        goto error_exit;
    }

    // event loop
    while (!interrupted) {
        printf("Waiting for events...\n");
        if (VMI_FAILURE == vmi_events_listen(vmi,500)) {
            fprintf(stderr, "Failed to listen on events\n");
            goto error_exit;
        }
    }
    printf("Finished with test.\n");

    retcode = 0;
error_exit:
    vmi_pause_vm(vmi);
    // restore opcode if needed
    if (saved_opcode) {
        printf("Restore previous opcode at 0x%" PRIx64 "\n", sym_vaddr);
        vmi_write_va(vmi, sym_vaddr, 0, sizeof(BREAKPOINT), &saved_opcode, NULL);
    }

    // cleanup queue
    if (vmi_are_events_pending(vmi))
        vmi_events_listen(vmi, 0);

    vmi_clear_event(vmi, &int_event, NULL);
    vmi_clear_event(vmi, &sstep_event, NULL);

    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}

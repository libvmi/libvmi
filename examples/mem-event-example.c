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

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

static bool interrupted = false;

static void close_handler(int sig)
{
    (void)sig;
    interrupted = true;
}

event_response_t mem_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi;

    char str_access[4] = {'_', '_', '_', '\0'};
    if (event->mem_event.out_access & VMI_MEMACCESS_R) str_access[0] = 'R';
    if (event->mem_event.out_access & VMI_MEMACCESS_W) str_access[1] = 'W';
    if (event->mem_event.out_access & VMI_MEMACCESS_X) str_access[2] = 'X';

    printf("%s: at 0x%"PRIx64", on frame 0x%"PRIx64", permissions: %s\n",
           __func__, event->x86_regs->rip, event->mem_event.gfn, str_access);

    // Relax the memory permission by clearing the event,
    // so that we can allow the CPU that triggered this event to continue execution
    vmi_clear_event(vmi, event, NULL);
    // One step forward and then this function will automatically re-register the event
    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

    return VMI_EVENT_RESPONSE_NONE;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    vmi_mode_t mode = {0};
    vmi_event_t mem_event = {0};
    struct sigaction act = {0};
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;

    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name of VM> [<socket path>]\n", argv[0]);
        return retcode;
    }

    // Arg 1 is the VM name.
    char *name = argv[1];


    // kvmi socket ?
    if (argc == 3) {
        char *path = argv[2];

        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    if (VMI_FAILURE == vmi_get_access_mode(NULL, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, &mode)) {
        fprintf(stderr, "Failed to get access mode\n");
        goto error_exit;
    }

    if (VMI_FAILURE ==
            vmi_init(&vmi, mode, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, NULL)) {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        goto error_exit;
    }

    vmi_init_paging(vmi, 0);
    printf("LibVMI init succeeded!\n");

    // pause vm
    if (VMI_FAILURE ==  vmi_pause_vm(vmi)) {
        fprintf(stderr, "Failed to pause vm\n");
        goto error_exit;
    }

    // get rip
    uint64_t rip;
    if (VMI_FAILURE == vmi_get_vcpureg(vmi, &rip, RIP, 0)) {
        fprintf(stderr, "Failed to get current RIP\n");
        goto error_exit;
    }

    // get dtb
    uint64_t cr3;
    if (VMI_FAILURE == vmi_get_vcpureg(vmi, &cr3, CR3, 0)) {
        fprintf(stderr, "Failed to get current CR3\n");
        goto error_exit;
    }
    uint64_t dtb = cr3 & ~(0xfff);

    // get gpa
    uint64_t paddr;
    if (VMI_FAILURE == vmi_pagetable_lookup(vmi, dtb, rip, &paddr)) {
        fprintf(stderr, "Failed to find current paddr\n");
        goto error_exit;
    }

    uint64_t gfn = paddr >> 12;
    /* register a mem event */
    SETUP_MEM_EVENT(&mem_event, gfn, VMI_MEMACCESS_X, mem_cb, false);

    printf("Setting X memory event at RIP 0x%"PRIx64", GPA 0x%"PRIx64", GFN 0x%"PRIx64"\n",
           rip, paddr, gfn);
    if (VMI_FAILURE == vmi_register_event(vmi, &mem_event)) {
        fprintf(stderr, "Failed to register mem event\n");
        goto error_exit;
    }

    // resuming
    if (VMI_FAILURE == vmi_resume_vm(vmi)) {
        fprintf(stderr, "Failed to resume vm\n");
        goto error_exit;
    }

    printf("Waiting for events...\n");
    while (!interrupted) {
        vmi_events_listen(vmi,500);
    }
    printf("Finished with test.\n");

    retcode = 0;
error_exit:
    vmi_clear_event(vmi, &mem_event, NULL);

    vmi_resume_vm(vmi);

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}

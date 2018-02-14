/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
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

reg_t cr3, rip;
vmi_pid_t pid;
vmi_event_t cr3_event;
vmi_event_t mm_event;

addr_t rip_pa;

int mm_enabled;

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

void print_event(vmi_event_t *event)
{
    printf("\tPAGE ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %u)\n",
           (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
           (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
           (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
           event->mem_event.gfn,
           event->mem_event.offset,
           event->mem_event.gla,
           event->vcpu_id
          );
}

event_response_t step_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    printf("Re-registering event\n");
    vmi_register_event(vmi, event);
    return 0;
}

event_response_t mm_callback(vmi_instance_t vmi, vmi_event_t *event)
{

    vmi_pid_t current_pid = -1;
    vmi_get_vcpureg(vmi, &cr3, CR3, 0);
    vmi_dtb_to_pid(vmi, cr3, &current_pid);

    reg_t rip_test;
    vmi_get_vcpureg(vmi, &rip_test, RIP, 0);

    printf("Memevent: {\n\tPID %u. RIP 0x%lx:\n", current_pid, rip_test);

    print_event(event);

    if ( current_pid == pid && event->mem_event.gla == rip) {
        printf("\tCought the original RIP executing again!");
        vmi_clear_event(vmi, event, NULL);
        interrupted = 1;
    } else {
        printf("\tEvent on same page, but not the same RIP");
        vmi_clear_event(vmi, event, NULL);

        /* These two calls are equivalent */
        //vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
        vmi_step_event(vmi, event, event->vcpu_id, 1, step_callback);
    }

    printf("\n}\n");
    return 0;
}

event_response_t cr3_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi_pid_t current_pid = -1;
    vmi_dtb_to_pid(vmi, event->reg_event.value, &current_pid);
    printf("PID %i with CR3=%"PRIx64" executing on vcpu %u.\n", current_pid, event->reg_event.value, event->vcpu_id);

    if (current_pid == pid) {
        if (!mm_enabled) {
            mm_enabled = 1;
            printf(" -- Enabling mem-event\n");
            vmi_register_event(vmi, &mm_event);
        }
    } else {
        if (mm_enabled) {
            mm_enabled = 0;
            printf(" -- Disabling mem-event\n");
            vmi_clear_event(vmi, &mm_event, NULL);
        }
    }
    return 0;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = NULL;
    status_t status = VMI_SUCCESS;
    addr_t gfn;

    struct sigaction act;

    mm_enabled=0;

    char *name = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name of VM>\n", argv[0]);
        exit(1);
    }

    // Arg 1 is the VM name.
    name = argv[1];

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    // Initialize the libvmi library.
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS,
                              NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    printf("LibVMI init succeeded!\n");

    vmi_pause_vm(vmi);

    SETUP_REG_EVENT(&cr3_event, CR3, VMI_REGACCESS_W, 0, cr3_callback);
    vmi_register_event(vmi, &cr3_event);

    // Setup a mem event for tracking memory at the current instruction's page
    // But don't install it; that will be done by the cr3 handler.

    vmi_get_vcpureg(vmi, &rip, RIP, 0);
    vmi_get_vcpureg(vmi, &cr3, CR3, 0);

    printf("Current value of RIP is 0x%lx\n", rip);
    rip -= 0x1;

    vmi_dtb_to_pid(vmi, cr3, &pid);
    if (pid==4) {
        vmi_translate_kv2p(vmi, rip, &rip_pa);
    } else {
        vmi_translate_uv2p(vmi, rip, pid, &rip_pa);
    }

    gfn = rip_pa >> 12;
    printf("Preparing memory event to catch next RIP 0x%lx, PA 0x%lx, page 0x%lx for PID %u\n",
           rip, rip_pa, gfn, pid);
    SETUP_MEM_EVENT(&mm_event, gfn, VMI_MEMACCESS_X, mm_callback, 0);

    vmi_resume_vm(vmi);

    while (!interrupted) {
        status = vmi_events_listen(vmi,500);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }
    printf("Finished with test.\n");

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    return 0;
}

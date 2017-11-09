/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Steven Maresca (steven.maresca@zentific.com)
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

vmi_event_t interrupt_event;

event_response_t int3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    printf("Int 3 happened: GFN=%"PRIx64" RIP=%"PRIx64" Length: %"PRIu32"\n",
           event->interrupt_event.gfn, event->interrupt_event.gla,
           event->interrupt_event.insn_length);

    /* This callback assumes that all INT3 events are caused by
     *  a debugger or similar inside the guest, and therefore
     *  unconditionally reinjects the interrupt.
     */
    event->interrupt_event.reinject = 1;

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

    return 0;
}

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi;
    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    char *name = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: interrupt_events_example <name of VM>\n");
        exit(1);
    }

    // Arg 1 is the VM name.
    name = argv[1];

    // Initialize the libvmi library.
    if (VMI_FAILURE ==
            vmi_init(&vmi, VMI_XEN, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    printf("LibVMI init succeeded!\n");

    /* Register event to track INT3 interrupts */
    memset(&interrupt_event, 0, sizeof(vmi_event_t));
    interrupt_event.version = VMI_EVENTS_VERSION;
    interrupt_event.type = VMI_EVENT_INTERRUPT;
    interrupt_event.interrupt_event.intr = INT3;
    interrupt_event.callback = int3_cb;

    vmi_register_event(vmi, &interrupt_event);

    printf("Waiting for events...\n");
    while (!interrupted) {
        vmi_events_listen(vmi,500);
    }
    printf("Finished with test.\n");

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    return 0;
}

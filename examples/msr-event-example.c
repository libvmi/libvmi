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

vmi_event_t msr_event;

event_response_t msr_write_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    printf("MSR write happened: MSR=%x Value=%lx\n", event->reg_event.msr, event->reg_event.value);
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
        fprintf(stderr, "Usage: msr_events_example <name of VM>\n");
        exit(1);
    }

    // Arg 1 is the VM name.
    name = argv[1];

    /* initialize the libvmi library */
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS,
                              NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    printf("LibVMI init succeeded!\n");

    /* Register event to track any writes to a MSR. */
    memset(&msr_event, 0, sizeof(vmi_event_t));
    msr_event.version = VMI_EVENTS_VERSION;
    msr_event.type = VMI_EVENT_REGISTER;
    msr_event.reg_event.reg = MSR_ALL;
    msr_event.reg_event.in_access = VMI_REGACCESS_W;
    msr_event.callback = msr_write_cb;

    vmi_register_event(vmi, &msr_event);

    printf("Waiting for events...\n");
    while (!interrupted) {
        vmi_events_listen(vmi,500);
    }
    printf("Finished with test.\n");

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    return 0;
}

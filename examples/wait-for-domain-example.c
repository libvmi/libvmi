/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Alexandru Isaila (aisaila@bitdefender.com)
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
#include <signal.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}
vmi_event_t watch_event = {0};

event_response_t wait_for_domain(__attribute__((unused)) vmi_instance_t vmi, vmi_event_t *event)
{

    if ( event->watch_event.created )
        printf("domain %d with uuid %s created\n", event->watch_event.domain, event->watch_event.uuid);
    else
        printf("domain %d with uuid %s deleted\n", event->watch_event.domain, event->watch_event.uuid);

    return 1;
}

int main ()
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

    // Initialize the libvmi library.
    if (VMI_FAILURE ==
            vmi_init(&vmi, VMI_XEN, NULL, VMI_INIT_DOMAINWATCH, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    printf("LibVMI init succeeded!\n");
    watch_event.version = VMI_EVENTS_VERSION;
    watch_event.type = VMI_EVENT_DOMAIN_WATCH;
    watch_event.callback = wait_for_domain;

    if (vmi_register_event(vmi, &watch_event) == VMI_FAILURE)
        printf("Failed to register event\n");

    printf("Wait for domains\n");

    while (!interrupted) {
        vmi_events_listen(vmi,500);
    }

    printf("Finished with test.\n");

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    return 0;
}

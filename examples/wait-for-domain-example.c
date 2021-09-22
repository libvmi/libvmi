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

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    vmi_mode_t mode = {0};
    struct sigaction act;
    vmi_init_data_t *init_data = NULL;
    char *name = NULL;
    int retcode = 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name of VM> [<socket>]\n", argv[0]);
        return retcode;
    }

    name = argv[1];

    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    // KVMi socket ?
    if (argc == 3) {
        char *path = argv[2];

        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    /* get access mode */
    if (VMI_FAILURE == vmi_get_access_mode(NULL, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, &mode)) {
        fprintf(stderr, "Failed to get access mode\n");
        goto error_exit;
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
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

    retcode = 0;
error_exit:
    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}

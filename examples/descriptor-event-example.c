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

event_response_t desc_cb(
    __attribute__((unused)) vmi_instance_t vmi,
    vmi_event_t *event)
{
    if (!event || !event->data) {
        fprintf(stderr, "%s: invalid parameters\n", __func__);
        return VMI_EVENT_RESPONSE_NONE;
    }
    int *stats = (int*)event->data;
    char *desc_str = NULL;
    switch (event->descriptor_event.descriptor) {
        case VMI_DESCRIPTOR_IDTR:
            desc_str = "IDTR";
            stats[VMI_DESCRIPTOR_IDTR] += 1;
            break;
        case VMI_DESCRIPTOR_GDTR:
            desc_str = "GDTR";
            stats[VMI_DESCRIPTOR_GDTR] += 1;
            break;
        case VMI_DESCRIPTOR_LDTR:
            desc_str = "LDTR";
            stats[VMI_DESCRIPTOR_LDTR] += 1;
            break;
        case VMI_DESCRIPTOR_TR:
            desc_str = "TR";
            stats[VMI_DESCRIPTOR_TR] += 1;
            break;
        default:
            fprintf(stderr, "Unexpected descriptor ID %d\n",
                    event->descriptor_event.descriptor);
            return VMI_EVENT_RESPONSE_NONE;
    }

    printf("[%d] Descriptor event: %s access on %s\n",
           event->vcpu_id,
           (event->descriptor_event.is_write) ? "write" : "read",
           desc_str);

    return VMI_EVENT_RESPONSE_NONE;
}

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    vmi_mode_t mode = {0};
    vmi_init_data_t *init_data = NULL;
    vmi_event_t descriptor_event = {0};
    struct sigaction act = {0};
    int retcode = 1;

    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    char *name = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name of VM> [<socket path>]\n", argv[0]);
        return retcode;
    }

    // Arg 1 is the VM name.
    name = argv[1];

    // kvmi socket ?
    if (argc == 3) {
        char *path = argv[2];

        init_data = malloc(sizeof(vmi_init_data_t)+ sizeof(vmi_init_data_entry_t));
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

    printf("LibVMI init succeeded!\n");

    /* Register event to track descriptor events */
    memset(&descriptor_event, 0, sizeof(vmi_event_t));
    descriptor_event.version = VMI_EVENTS_VERSION;
    descriptor_event.type = VMI_EVENT_DESCRIPTOR_ACCESS;
    descriptor_event.callback = &desc_cb;
    // record stats
    // VMI_DESCRIPTOR_TR is MAX value
    int stats[VMI_DESCRIPTOR_TR+1] = {0};
    descriptor_event.data = (void*)&stats;

    vmi_register_event(vmi, &descriptor_event);

    printf("Waiting for events...\n");
    while (!interrupted) {
        if (VMI_FAILURE == vmi_events_listen(vmi,500))
            goto error_exit;
    }
    printf("Finished with test.\n");

    // display stats
    printf("Statistics:\n");
    printf("\tIDTR access: %d\n", stats[VMI_DESCRIPTOR_IDTR]);
    printf("\tGDTR access: %d\n", stats[VMI_DESCRIPTOR_GDTR]);
    printf("\tLDTR access: %d\n", stats[VMI_DESCRIPTOR_LDTR]);
    printf("\tTR access: %d\n", stats[VMI_DESCRIPTOR_TR]);

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

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

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

event_response_t cb(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi; // just to silence unused variable warning

    printf("PAGE ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %"PRIu32")\n",
           (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
           (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
           (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
           event->mem_event.gfn,
           event->mem_event.offset,
           event->mem_event.gla,
           event->vcpu_id
          );
    return VMI_EVENT_RESPONSE_EMULATE;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = NULL;
    vmi_event_t event = {0};
    status_t status = VMI_SUCCESS;
    addr_t addr = 0;
    char *name = NULL;
    vmi_init_data_t *init_data = NULL;
    struct sigaction act = {0};
    int rc = 1;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <name of VM> <kernel virtual address trap in hex> [<socket>]\n", argv[0]);
        return rc;
    }

    // Arg 1 is the VM name.
    name = argv[1];
    addr = (addr_t) strtoul(argv[2], NULL, 16);

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

    // Initialize the libvmi library.
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS,
                              init_data, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto leave;
    }

    printf("LibVMI init succeeded!\n");

    memset(&event, 0, sizeof(vmi_event_t));
    event.version = VMI_EVENTS_VERSION;
    event.type = VMI_EVENT_MEMORY;
    event.mem_event.gfn >>= 12;
    event.mem_event.in_access = VMI_MEMACCESS_X;
    event.callback = cb;

    if ( VMI_FAILURE == vmi_translate_kv2p(vmi, addr, &event.mem_event.gfn) )
        goto leave;

    if ( VMI_FAILURE == vmi_register_event(vmi, &event) )
        goto leave;

    while (!interrupted) {
        printf("Waiting for events...\n");
        status = vmi_events_listen(vmi,500);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }
    printf("Finished with test.\n");

    rc = 0;
leave:
    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return rc;
}

/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Dorian Eikenberg (dorian.eikenberg@gdata.de)
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
#include <libvmi/events.h>
#include <libvmi/slat.h>

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;

    char *name = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name of VM> [<socket>]\n", argv[0]);
        return retcode;
    }

    // Arg 1 is the VM name.
    name = argv[1];

    if (argc == 3) {
        char *path = argv[2];

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

    bool state = false;
    vmi_slat_state(vmi, &state);
    printf("SLAT feature active: %s\n", state ? "true" : "false");

    if (!state) {
        if (vmi_slat_control(vmi, true) == VMI_FAILURE) {
            printf("Unable to activate SLAT\n");
            goto error_exit;
        }
    }

    uint16_t new_view = 1;
    if (vmi_slat_create(vmi, &new_view) == VMI_FAILURE) {
        printf("Unable to create new view\n");
        goto error_exit;
    }

    if (vmi_slat_switch(vmi, new_view) == VMI_FAILURE) {
        printf("Failed to switch to view %u\n", new_view);
        goto error_exit;
    }
    if (vmi_slat_switch(vmi, 0) == VMI_FAILURE) {
        printf("Failed to switch to view 0\n");
        goto error_exit;
    }

    if (vmi_slat_destroy(vmi, new_view) == VMI_FAILURE) {
        printf("Failed to destroy view %u\n", new_view);
    }

    retcode = 0;
error_exit:
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}

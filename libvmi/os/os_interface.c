/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
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

#include "private.h"

status_t os_destroy(vmi_instance_t vmi)
{
    status_t status = VMI_SUCCESS;

    if (vmi->os_interface == NULL ) {
        errprint("VMI_ERROR: No OS initialized\n");
        status = VMI_FAILURE;
    } else if (vmi->os_interface->os_teardown != NULL ) {
        status = vmi->os_interface->os_teardown(vmi);
    }

    if (vmi->os_interface != NULL ) {
        free(vmi->os_interface);
    }
    vmi->os_interface = NULL;

    if (vmi->os_data != NULL ) {
        free(vmi->os_data);
    }
    vmi->os_data = NULL;

    return status;
}

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

#include "libvmi.h"
#include "private.h"
#include "arch_interface.h"
#include "intel.h"
#include "amd64.h"
#include <stdlib.h>

status_t arch_init(vmi_instance_t vmi) {

    status_t ret = VMI_FAILURE;

    if (vmi->arch_interface != NULL) {
        dbprint(VMI_DEBUG_CORE, "Resetting architecture interface");
        bzero(vmi->arch_interface, sizeof(struct arch_interface));
    }

    if(vmi->page_mode == VMI_PM_UNKNOWN) {
        if(VMI_FAILURE == find_page_mode_live(vmi)) {
            return ret;
        }
    }

    switch(vmi->page_mode) {
        case VMI_PM_LEGACY:
        case VMI_PM_PAE:
            ret = intel_init(vmi);
            break;
        case VMI_PM_IA32E:
            ret = amd64_init(vmi);
            break;
        default:
            break;
    }

    return ret;
}

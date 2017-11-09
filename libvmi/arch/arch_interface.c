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

#include <stdlib.h>

#include "private.h"
#include "arch/arch_interface.h"
#include "arch/intel.h"
#include "arch/amd64.h"
#include "arch/arm_aarch32.h"
#include "arch/arm_aarch64.h"

status_t arch_init(vmi_instance_t vmi)
{

    status_t ret = VMI_FAILURE;

    if (vmi->arch_interface != NULL) {
        dbprint(VMI_DEBUG_CORE, "-- Clearing and setting new architecture interface\n");
        bzero(vmi->arch_interface, sizeof(struct arch_interface));
    }

    if (vmi->page_mode == VMI_PM_UNKNOWN) {
        if (VMI_FAILURE == find_page_mode_live(vmi, 0, NULL)) {
            return ret;
        }
    }

    switch (vmi->page_mode) {
        case VMI_PM_LEGACY: /* fallthrough */
        case VMI_PM_PAE:
            ret = intel_init(vmi);
            break;
        case VMI_PM_IA32E:
            ret = amd64_init(vmi);
            break;
        case VMI_PM_AARCH32:
            ret = aarch32_init(vmi);
            break;
        case VMI_PM_AARCH64:
            ret = aarch64_init(vmi);
            break;
        case VMI_PM_UNKNOWN: /* fallthrough */
        default:
            ret = VMI_FAILURE;
            break;
    }

    if (VMI_FAILURE == ret) {
        vmi->page_mode = VMI_PM_UNKNOWN;
    }

    return ret;
}

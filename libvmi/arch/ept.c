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

status_t v2p_ept_4l (vmi_instance_t vmi, addr_t UNUSED(npt), page_mode_t UNUSED(npm), addr_t pt, addr_t vaddr, page_info_t *info)
{
    return vmi->arch_interface.lookup[VMI_PM_IA32E](vmi, 0, 0, pt, vaddr, info);
}

GSList* get_pages_ept_4l(vmi_instance_t vmi, addr_t UNUSED(npt), page_mode_t UNUSED(npm), addr_t pt)
{
    return vmi->arch_interface.get_pages[VMI_PM_IA32E](vmi, 0, 0, pt);
}

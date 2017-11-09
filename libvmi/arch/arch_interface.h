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

#ifndef ARCH_INTERFACE_H_
#define ARCH_INTERFACE_H_

#include "private.h"

typedef status_t (*arch_v2p_t)
(vmi_instance_t vmi,
 addr_t dtb,
 addr_t vaddr,
 page_info_t *info);
typedef GSList* (*arch_get_va_pages_t)
(vmi_instance_t vmi,
 addr_t dtb);

struct arch_interface {
    arch_v2p_t v2p;
    arch_get_va_pages_t get_va_pages;
};
typedef struct arch_interface *arch_interface_t;

status_t arch_init(vmi_instance_t vmi);

#endif /* ARCH_INTERFACE_H_ */

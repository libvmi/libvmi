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

typedef status_t (*arch_lookup_t)
(vmi_instance_t vmi,
 addr_t npt,
 page_mode_t npm,
 addr_t pt,
 addr_t addr,
 page_info_t *info);
typedef GSList* (*arch_get_pages_t)
(vmi_instance_t vmi,
 addr_t npt,
 page_mode_t npm,
 addr_t dtb);

typedef struct arch_interface {
    arch_lookup_t lookup[VMI_PM_EPT_5L + 1];
    arch_get_pages_t get_pages[VMI_PM_EPT_5L + 1];
} arch_interface_t;

status_t get_vcpu_page_mode(vmi_instance_t vmi, unsigned long vcpu, page_mode_t *out_pm);
status_t arch_init(vmi_instance_t vmi);

static inline bool valid_npm(page_mode_t npm)
{
    return npm == VMI_PM_EPT_4L;
}

static inline bool valid_pm(page_mode_t pm)
{
    return pm >= VMI_PM_LEGACY && pm < VMI_PM_EPT_5L;
}

static inline
page_mode_t get_page_mode_x86(reg_t cr0, reg_t cr4, reg_t efer)
{
    if (!VMI_GET_BIT(cr0, 31))
        return VMI_PM_NONE;

    if (!VMI_GET_BIT(cr4, 5))
        return VMI_PM_LEGACY;

    if (!VMI_GET_BIT(efer, 8))
        return VMI_PM_PAE;

    return VMI_PM_IA32E;
}

void arch_init_lookup_tables(vmi_instance_t vmi);

#endif /* ARCH_INTERFACE_H_ */

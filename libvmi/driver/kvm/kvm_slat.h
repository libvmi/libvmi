/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
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


#ifndef KVM_SLAT_H
#define KVM_SLAT_H

#include "kvm_private.h"

status_t kvm_slat_state(__attribute__((unused)) vmi_instance_t vmi, bool *state);

status_t kvm_slat_control(__attribute__((unused)) vmi_instance_t vmi, __attribute__((unused)) bool state);

status_t kvm_create_view(vmi_instance_t vmi, uint16_t *view);

status_t kvm_destroy_view(vmi_instance_t vmi, uint16_t view);

status_t kvm_switch_view(vmi_instance_t vmi, uint16_t view);

status_t kvm_change_gfn(vmi_instance_t vmi,
                        uint16_t slat_idx,
                        addr_t old_gfn,
                        addr_t new_gfn);

static inline void kvm_init_slat(vmi_instance_t vmi)
{
#ifndef ENABLE_KVM_LEGACY
    vmi->driver.slat_state_ptr = &kvm_slat_state;
    vmi->driver.slat_control_ptr = &kvm_slat_control;
    vmi->driver.slat_create_ptr = &kvm_create_view;
    vmi->driver.slat_destroy_ptr = &kvm_destroy_view;
    vmi->driver.slat_switch_ptr = &kvm_switch_view;
    vmi->driver.slat_change_gfn_ptr = &kvm_change_gfn;
#endif
}

#endif

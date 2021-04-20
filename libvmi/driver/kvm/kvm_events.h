/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the KVMAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
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
#ifndef KVM_EVENTS_H
#define KVM_EVENTS_H

#include "private.h"
#include "kvm_private.h"

status_t
kvm_events_init(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);

void
kvm_events_destroy(vmi_instance_t vmi);

status_t
kvm_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout);

int
kvm_are_events_pending(
    vmi_instance_t vmi);

status_t
kvm_set_reg_access(
    vmi_instance_t vmi,
    reg_event_t* event);

status_t
kvm_set_intr_access(
    vmi_instance_t vmi,
    interrupt_event_t* event,
    bool enabled);

status_t
kvm_set_mem_access(
    vmi_instance_t vmi,
    addr_t gpfn,
    vmi_mem_access_t page_access_flag,
    uint16_t vmm_pagetable_id);

status_t
kvm_set_desc_access_event(
    vmi_instance_t,
    bool enabled);

status_t
kvm_start_single_step(
    vmi_instance_t vmi,
    single_step_event_t *event);

status_t
kvm_stop_single_step(
    vmi_instance_t vmi,
    uint32_t vcpu);

status_t
kvm_shutdown_single_step(
    vmi_instance_t vmi);

status_t
kvm_get_next_event(
    kvm_instance_t *kvm,
    struct kvmi_dom_event **event,
    kvmi_timeout_t timeout);

status_t
kvm_set_cpuid_event(
    vmi_instance_t vmi,
    bool enable);

#endif // KVM_EVENTS_H

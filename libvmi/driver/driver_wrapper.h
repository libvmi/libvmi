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

#ifndef DRIVER_WRAPPER_H
#define DRIVER_WRAPPER_H

#include "private.h"

/*
 * The following functions are safety-wrappers that should be used internally
 * instead of calling the functions directly on the driver.
 */

static inline void
driver_destroy(
    vmi_instance_t vmi)
{
    if (vmi->driver.initialized && vmi->driver.destroy_ptr)
        vmi->driver.destroy_ptr(vmi);

    bzero(&vmi->driver, sizeof(driver_interface_t));
}

static inline uint64_t
driver_get_id_from_name(
    vmi_instance_t vmi,
    const char *name)
{
    if (vmi->driver.initialized && vmi->driver.get_id_from_name_ptr) {
        return vmi->driver.get_id_from_name_ptr(vmi, name);
    } else {
        dbprint
        (VMI_DEBUG_DRIVER, "WARNING: driver_get_id_from_name function not implemented.\n");
        return 0;
    }
}

static inline status_t
driver_get_name_from_id(
    vmi_instance_t vmi,
    uint64_t domid,
    char **name)
{
    if (vmi->driver.initialized && vmi->driver.get_name_from_id_ptr) {
        return vmi->driver.get_name_from_id_ptr(vmi, domid, name);
    } else {
        dbprint
        (VMI_DEBUG_DRIVER, "WARNING: driver_get_name_from_id function not implemented.\n");
        return 0;
    }
}

static inline uint64_t
driver_get_id(
    vmi_instance_t vmi)
{
    if (vmi->driver.initialized && vmi->driver.get_id_ptr) {
        return vmi->driver.get_id_ptr(vmi);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_id function not implemented.\n");
        return 0;
    }
}

static inline void
driver_set_id(
    vmi_instance_t vmi,
    uint64_t id)
{
    if (vmi->driver.initialized && vmi->driver.set_id_ptr) {
        return vmi->driver.set_id_ptr(vmi, id);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_id function not implemented.\n");
        return;
    }
}

static inline status_t
driver_check_id(
    vmi_instance_t vmi,
    uint64_t id)
{
    if (vmi->driver.initialized && vmi->driver.check_id_ptr) {
        return vmi->driver.check_id_ptr(vmi, id);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_check_id function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_get_name(
    vmi_instance_t vmi,
    char **name)
{
    if (vmi->driver.initialized && vmi->driver.get_name_ptr) {
        return vmi->driver.get_name_ptr(vmi, name);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_name function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline void
driver_set_name(
    vmi_instance_t vmi,
    const char *name)
{
    if (vmi->driver.initialized && vmi->driver.set_name_ptr) {
        return vmi->driver.set_name_ptr(vmi, name);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_name function not implemented.\n");
        return;
    }
}

static inline status_t
driver_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *max_physical_address)
{
    if (vmi->driver.initialized && vmi->driver.get_memsize_ptr) {
        return vmi->driver.get_memsize_ptr(vmi, allocated_ram_size, max_physical_address);
    } else {
        dbprint
        (VMI_DEBUG_DRIVER, "WARNING: driver_get_memsize function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
    if (vmi->driver.initialized && vmi->driver.get_vcpureg_ptr) {
        return vmi->driver.get_vcpureg_ptr(vmi, value, reg, vcpu);
    } else {
        dbprint
        (VMI_DEBUG_DRIVER, "WARNING: driver_get_vcpureg function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t* regs,
    unsigned long vcpu)
{
    if (vmi->driver.initialized && vmi->driver.get_vcpuregs_ptr) {
        return vmi->driver.get_vcpuregs_ptr(vmi, regs, vcpu);
    } else {
        dbprint
        (VMI_DEBUG_DRIVER, "WARNING: driver_get_vcpuregs function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu)
{
    if (vmi->driver.initialized && vmi->driver.set_vcpureg_ptr) {
        return vmi->driver.set_vcpureg_ptr(vmi, value, reg, vcpu);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_vcpureg function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
    if (vmi->driver.initialized && vmi->driver.set_vcpuregs_ptr) {
        return vmi->driver.set_vcpuregs_ptr(vmi, regs, vcpu);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_vcpuregs function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline void *
driver_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    if (vmi->driver.initialized && vmi->driver.read_page_ptr) {
        return vmi->driver.read_page_ptr(vmi, page);
    } else {
        dbprint
        (VMI_DEBUG_DRIVER, "WARNING: driver_read_page function not implemented.\n");
        return NULL;
    }
}

static inline status_t
driver_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    if (vmi->driver.initialized && vmi->driver.write_ptr) {
        return vmi->driver.write_ptr(vmi, paddr, buf, length);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_write function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline int
driver_is_pv(
    vmi_instance_t vmi)
{
    if (vmi->driver.initialized && vmi->driver.is_pv_ptr) {
        return vmi->driver.is_pv_ptr(vmi);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_is_pv function not implemented.\n");
        return 0;
    }
}

static inline status_t
driver_pause_vm(
    vmi_instance_t vmi)
{
    if (vmi->driver.initialized && vmi->driver.pause_vm_ptr) {
        return vmi->driver.pause_vm_ptr(vmi);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_pause_vm function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_resume_vm(
    vmi_instance_t vmi)
{
    if (vmi->driver.initialized && vmi->driver.resume_vm_ptr) {
        return vmi->driver.resume_vm_ptr(vmi);
    } else {
        dbprint
        (VMI_DEBUG_DRIVER, "WARNING: driver_resume_vm function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_shm_snapshot_vm(
    vmi_instance_t vmi)
{
    if (vmi->driver.initialized && vmi->driver.create_shm_snapshot_ptr) {
        return vmi->driver.create_shm_snapshot_ptr(vmi);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_shm_snapshot_vm function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_destroy_shm_snapshot_vm(
    vmi_instance_t vmi)
{
    if (vmi->driver.initialized && vmi->driver.destroy_shm_snapshot_ptr) {
        return vmi->driver.destroy_shm_snapshot_ptr(vmi);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_destroy_shm_snapshot_vm function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline size_t
driver_get_dgpma(
    vmi_instance_t vmi,
    addr_t paddr,
    void **medial_addr_ptr,
    size_t count)
{
    if (vmi->driver.initialized && vmi->driver.get_dgpma_ptr) {
        return vmi->driver.get_dgpma_ptr(vmi, paddr, medial_addr_ptr, count);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: get_dgpma_ptr function not implemented.\n");
        return 0;
    }
    return 0;
}

static inline size_t
driver_get_dgvma(
    vmi_instance_t vmi,
    addr_t vaddr,
    pid_t pid,
    void** medial_addr_ptr,
    size_t count)
{
    if (vmi->driver.initialized && vmi->driver.get_dgvma_ptr) {
        return vmi->driver.get_dgvma_ptr(vmi, vaddr, pid, medial_addr_ptr, count);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: get_dgvma_ptr function not implemented.\n");
        return 0;
    }
    return 0;
}

static inline status_t
driver_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout)
{
    if (vmi->driver.initialized && vmi->driver.events_listen_ptr) {
        return vmi->driver.events_listen_ptr(vmi, timeout);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_events_listen function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline int
driver_are_events_pending(
    vmi_instance_t vmi)
{
    if (vmi->driver.initialized && vmi->driver.are_events_pending_ptr) {
        return vmi->driver.are_events_pending_ptr(vmi);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_are_events_pending function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_reg_access(
    vmi_instance_t vmi,
    reg_event_t *event)
{
    if (vmi->driver.initialized && vmi->driver.set_reg_access_ptr) {
        return vmi->driver.set_reg_access_ptr(vmi, event);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_reg_w_access function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_intr_access(
    vmi_instance_t vmi,
    interrupt_event_t *event,
    uint8_t enabled)
{
    if (vmi->driver.initialized && vmi->driver.set_intr_access_ptr) {
        return vmi->driver.set_intr_access_ptr(vmi, event, enabled);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_intr_access function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_mem_access(
    vmi_instance_t vmi,
    addr_t gpfn,
    vmi_mem_access_t page_access_flag,
    uint16_t vmm_pagetable_id)
{
    if (vmi->driver.initialized && vmi->driver.set_mem_access_ptr) {
        return vmi->driver.set_mem_access_ptr(vmi, gpfn, page_access_flag, vmm_pagetable_id);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_mem_access function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_start_single_step(
    vmi_instance_t vmi,
    single_step_event_t *event)
{
    if (vmi->driver.initialized && vmi->driver.start_single_step_ptr) {
        return vmi->driver.start_single_step_ptr(vmi, event);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_start_single_step function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_stop_single_step(
    vmi_instance_t vmi,
    unsigned long vcpu)
{
    if (vmi->driver.initialized && vmi->driver.stop_single_step_ptr) {
        return vmi->driver.stop_single_step_ptr(vmi, vcpu);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_stop_single_step function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_shutdown_single_step(
    vmi_instance_t vmi)
{
    if (vmi->driver.initialized && vmi->driver.shutdown_single_step_ptr) {
        return vmi->driver.shutdown_single_step_ptr(vmi);
    } else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_shutdown_single_step function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_guest_requested_event(
    vmi_instance_t vmi,
    bool enabled)
{
    if (vmi->driver.initialized && vmi->driver.set_guest_requested_ptr)
        return vmi->driver.set_guest_requested_ptr(vmi, enabled);
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_guest_requested function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_cpuid_event(
    vmi_instance_t vmi,
    bool enabled)
{
    if (vmi->driver.initialized && vmi->driver.set_cpuid_event_ptr)
        return vmi->driver.set_cpuid_event_ptr(vmi, enabled);
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_cpuid_event function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_debug_event(
    vmi_instance_t vmi,
    bool enabled)
{
    if (vmi->driver.initialized && vmi->driver.set_debug_event_ptr)
        return vmi->driver.set_debug_event_ptr(vmi, enabled);
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_debug_event function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_privcall_event(
    vmi_instance_t vmi,
    bool enabled)
{
    if (vmi->driver.initialized && vmi->driver.set_privcall_event_ptr)
        return vmi->driver.set_privcall_event_ptr(vmi, enabled);
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_privcall_event function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_desc_access_event(
    vmi_instance_t vmi,
    bool enabled)
{
    if (vmi->driver.initialized && vmi->driver.set_desc_access_event_ptr)
        return vmi->driver.set_desc_access_event_ptr(vmi, enabled);
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_desc_access_event function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_failed_emulation_event(
    vmi_instance_t vmi,
    bool enabled)
{
    if (vmi->driver.initialized && vmi->driver.set_failed_emulation_event_ptr)
        return vmi->driver.set_failed_emulation_event_ptr(vmi, enabled);
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_failed_emulation_event function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_slat_get_domain_state (
    vmi_instance_t vmi,
    bool *state )
{
    if (vmi->driver.initialized && vmi->driver.slat_get_domain_state_ptr ) {
        return vmi->driver.slat_get_domain_state_ptr (vmi, state);
    } else {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_get_domain_state function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_slat_set_domain_state (
    vmi_instance_t vmi,
    bool state )
{
    if (vmi->driver.initialized && vmi->driver.slat_set_domain_state_ptr ) {
        return vmi->driver.slat_set_domain_state_ptr (vmi, state);
    } else {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_set_domain_state function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_slat_create (
    vmi_instance_t vmi,
    uint16_t *slat_idx )
{
    if (vmi->driver.initialized && vmi->driver.slat_create_ptr) {
        return vmi->driver.slat_create_ptr (vmi, slat_idx);
    } else {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_create function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_slat_destroy (
    vmi_instance_t vmi,
    uint16_t slat_idx )
{
    if (vmi->driver.initialized && vmi->driver.slat_destroy_ptr) {
        return vmi->driver.slat_destroy_ptr (vmi, slat_idx);
    } else {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_destroy function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_slat_switch (
    vmi_instance_t vmi,
    uint16_t slat_idx )
{
    if (vmi->driver.initialized && vmi->driver.slat_switch_ptr) {
        return vmi->driver.slat_switch_ptr (vmi, slat_idx);
    } else {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_switch function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_slat_change_gfn (
    vmi_instance_t vmi,
    uint16_t slat_idx,
    addr_t old_gfn,
    addr_t new_gfn)
{
    if (vmi->driver.initialized && vmi->driver.slat_change_gfn_ptr) {
        return vmi->driver.slat_change_gfn_ptr (vmi, slat_idx, old_gfn, new_gfn);
    } else {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_change_gfn function not implemented.\n");
        return VMI_FAILURE;
    }
}

static inline status_t
driver_set_access_listener_required(
    vmi_instance_t vmi,
    bool required)
{
    if (vmi->driver.initialized && vmi->driver.set_access_required_ptr) {
        return vmi->driver.set_access_required_ptr (vmi, required);
    } else {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_change_gfn function not implemented.\n");
        return VMI_FAILURE;
    }
}

#endif /* DRIVER_WRAPPER_H */


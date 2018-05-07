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

#ifndef DRIVER_INTERFACE_H
#define DRIVER_INTERFACE_H

#include "private.h"

typedef struct driver_interface {
    status_t (*init_ptr) (
        vmi_instance_t,
        uint32_t init_flags,
        void *init_data);
    status_t (*init_vmi_ptr) (
        vmi_instance_t,
        uint32_t init_flags,
        void *init_data);
    void (*destroy_ptr) (
        vmi_instance_t);
    uint64_t (*get_id_from_name_ptr) (
        vmi_instance_t,
        const char *);
    status_t (*get_name_from_id_ptr) (
        vmi_instance_t,
        uint64_t,
        char **);
    uint64_t (*get_id_ptr) (
        vmi_instance_t);
    void (*set_id_ptr) (
        vmi_instance_t,
        uint64_t);
    status_t (*check_id_ptr) (
        vmi_instance_t,
        uint64_t);
    status_t (*get_name_ptr) (
        vmi_instance_t,
        char **);
    void (*set_name_ptr) (
        vmi_instance_t,
        const char *);
    status_t (*get_memsize_ptr) (
        vmi_instance_t,
        uint64_t *,
        addr_t *);
    status_t (*get_vcpureg_ptr) (
        vmi_instance_t,
        uint64_t *,
        reg_t,
        unsigned long);
    status_t (*get_vcpuregs_ptr) (
        vmi_instance_t,
        registers_t *,
        unsigned long);
    status_t(*set_vcpureg_ptr) (
        vmi_instance_t,
        uint64_t,
        reg_t,
        unsigned long);
    status_t(*set_vcpuregs_ptr) (
        vmi_instance_t,
        registers_t *,
        unsigned long);
    void *(*read_page_ptr) (
        vmi_instance_t,
        addr_t);
    status_t (*write_ptr) (
        vmi_instance_t,
        addr_t,
        void *,
        uint32_t);
    int (*is_pv_ptr) (
        vmi_instance_t);
    status_t (*pause_vm_ptr) (
        vmi_instance_t);
    status_t (*resume_vm_ptr) (
        vmi_instance_t);
    status_t (*create_shm_snapshot_ptr) (
        vmi_instance_t);
    status_t (*destroy_shm_snapshot_ptr) (
        vmi_instance_t);
    size_t (*get_dgpma_ptr) (
        vmi_instance_t,
        addr_t,
        void **,
        size_t);
    size_t (*get_dgvma_ptr) (
        vmi_instance_t,
        addr_t,
        pid_t,
        void**,
        size_t);
    status_t (*events_listen_ptr)(
        vmi_instance_t,
        uint32_t);
    int (*are_events_pending_ptr)(
        vmi_instance_t);
    status_t (*set_reg_access_ptr)(
        vmi_instance_t,
        reg_event_t*);
    status_t (*set_intr_access_ptr)(
        vmi_instance_t,
        interrupt_event_t*,
        bool enabled);
    status_t (*set_mem_access_ptr)(
        vmi_instance_t,
        addr_t gpfn,
        vmi_mem_access_t,
        uint16_t vmm_pagetable_id);
    status_t (*start_single_step_ptr)(
        vmi_instance_t,
        single_step_event_t*);
    status_t (*stop_single_step_ptr)(
        vmi_instance_t,
        uint32_t);
    status_t (*shutdown_single_step_ptr)(
        vmi_instance_t);
    status_t (*set_guest_requested_ptr)(
        vmi_instance_t,
        bool enabled);
    status_t (*set_cpuid_event_ptr)(
        vmi_instance_t,
        bool enabled);
    status_t (*set_debug_event_ptr)(
        vmi_instance_t,
        bool enabled);
    status_t (*set_privcall_event_ptr)(
        vmi_instance_t,
        bool enabled);
    status_t (*set_desc_access_event_ptr)(
        vmi_instance_t,
        bool enabled);
    status_t (*set_failed_emulation_event_ptr)(
        vmi_instance_t,
        bool enabled);
    status_t (*slat_get_domain_state_ptr)(
        vmi_instance_t vmi,
        bool *state);
    status_t (*slat_set_domain_state_ptr)(
        vmi_instance_t vmi,
        bool state);
    status_t (*slat_create_ptr)(
        vmi_instance_t vmi,
        uint16_t *view);
    status_t (*slat_destroy_ptr)(
        vmi_instance_t vmi,
        uint16_t view);
    status_t (*slat_switch_ptr)(
        vmi_instance_t vmi,
        uint16_t view);
    status_t (*slat_change_gfn_ptr)(
        vmi_instance_t vmi,
        uint16_t slat_idx,
        addr_t old_gfn,
        addr_t new_gfn);
    status_t (*set_access_required_ptr)(
        vmi_instance_t vmi,
        bool required);

    /* Driver-specific data storage. */
    void* driver_data;

    /* Set to true once driver is initialized. */
    bool initialized;

} driver_interface_t;

status_t driver_init_mode(
    const char *name,
    uint64_t domainid,
    uint64_t init_flags,
    void* init_data,
    vmi_mode_t *mode);

status_t driver_init(
    vmi_instance_t vmi,
    uint32_t init_flags,
    void *init_data);

status_t driver_init_vmi(
    vmi_instance_t vmi,
    uint32_t init_flags,
    void *init_data);

#endif /* DRIVER_INTERFACE_H */


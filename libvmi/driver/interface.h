/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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
#include <stdlib.h>

status_t driver_init_mode(
    vmi_instance_t vmi,
    unsigned long id,
    char *name);
status_t driver_init(
    vmi_instance_t vmi);
void driver_destroy(
    vmi_instance_t vmi);
unsigned long driver_get_id_from_name(
    vmi_instance_t vmi,
    char *name);
status_t driver_get_name_from_id(
    vmi_instance_t vmi,
    unsigned long domid,
    char **name);
unsigned long driver_get_id(
    vmi_instance_t vmi);
void driver_set_id(
    vmi_instance_t vmi,
    unsigned long id);
status_t driver_check_id(
    vmi_instance_t vmi,
    unsigned long id);
status_t driver_get_name(
    vmi_instance_t vmi,
    char **name);
void driver_set_name(
    vmi_instance_t vmi,
    char *name);
status_t driver_get_memsize(
    vmi_instance_t vmi,
    uint64_t *size);
status_t driver_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu);
status_t driver_set_vcpureg(
    vmi_instance_t vmi,
    reg_t value,
    registers_t reg,
    unsigned long vcpu);
status_t xen_get_address_width(
    vmi_instance_t vmi,
    uint8_t * width);
void *driver_read_page(
    vmi_instance_t vmi,
    addr_t page);
status_t driver_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length);
int driver_is_pv(
    vmi_instance_t vmi);
status_t driver_pause_vm(
    vmi_instance_t vmi);
status_t driver_resume_vm(
    vmi_instance_t vmi);
#if ENABLE_SHM_SNAPSHOT == 1
/* "shm-snapshot" feature is applicable to
 * hypervisor drivers (e.g. KVM, Xen), but not to the
 * other drivers (e.g. File). */
status_t driver_shm_snapshot_vm(
    vmi_instance_t vmi);
status_t driver_destroy_shm_snapshot_vm(
    vmi_instance_t vmi);
size_t driver_get_dgpma(
    vmi_instance_t vmi,
    addr_t paddr,
    void** guest_mapping_paddr,
    size_t count);
size_t driver_get_dgvma(
    vmi_instance_t vmi,
    addr_t vaddr,
    pid_t pid,
    void** guest_mapping_vaddr,
    size_t count);
#endif
status_t driver_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout);
status_t driver_set_mem_access(
    vmi_instance_t vmi,
    mem_event_t event,
    vmi_mem_access_t page_access_flag);
status_t driver_set_intr_access(
    vmi_instance_t vmi,
    interrupt_event_t event,
    uint8_t enabled);
status_t driver_set_reg_access(
    vmi_instance_t vmi,
    reg_event_t event);
status_t driver_start_single_step(
    vmi_instance_t vmi,
    single_step_event_t event);
status_t driver_stop_single_step(
    vmi_instance_t vmi,
    unsigned long vcpu);
status_t driver_shutdown_single_step(
    vmi_instance_t vmi);
status_t
driver_get_address_width(
    vmi_instance_t vmi,
    uint8_t * width);

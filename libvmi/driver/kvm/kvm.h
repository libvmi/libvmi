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

#ifndef KVM_H
#define KVM_H

status_t kvm_init(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);

status_t kvm_init_vmi(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);

void kvm_destroy(
    vmi_instance_t vmi);
uint64_t kvm_get_id_from_name(
    vmi_instance_t vmi,
    const char *name);

status_t kvm_get_name_from_id(
    vmi_instance_t vmi,
    uint64_t domainid,
    char **name);

uint64_t kvm_get_id(
    vmi_instance_t vmi);

void kvm_set_id(
    vmi_instance_t vmi,
    uint64_t domainid);

status_t kvm_check_id(
    vmi_instance_t vmi,
    uint64_t domainid);

status_t kvm_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length);

status_t kvm_get_name(
    vmi_instance_t vmi,
    char **name);

void kvm_set_name(
    vmi_instance_t vmi,
    const char *name);

status_t kvm_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocate_ram_size,
    addr_t *maximum_physical_address);

status_t kvm_request_page_fault(
    vmi_instance_t vmi,
    unsigned long vcpu,
    uint64_t virtual_address,
    uint32_t error_code);

status_t kvm_get_tsc_info(
    vmi_instance_t vmi,
    uint32_t *tsc_mode,
    uint64_t *elapsed_nsec,
    uint32_t *gtsc_khz,
    uint32_t *incarnation);

addr_t kvm_pfn_to_mfn(
    vmi_instance_t vmi,
    addr_t pfn);

void *kvm_read_page(
    vmi_instance_t vmi,
    addr_t page);

int kvm_is_pv(
    vmi_instance_t vmi);

status_t kvm_test(
    uint64_t domainid,
    const char *name,
    uint64_t init_flags,
    vmi_init_data_t* init_data);

// pause & resume
status_t kvm_pause_vm(
    vmi_instance_t vmi);

status_t kvm_resume_vm(
    vmi_instance_t vmi);

// registers
status_t kvm_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu);

status_t kvm_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu);

status_t kvm_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu);
status_t kvm_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *registers,
    unsigned long vcpu);

static inline status_t
driver_kvm_setup(vmi_instance_t vmi)
{
    driver_interface_t driver = { 0 };
    driver.initialized = true;
    driver.init_ptr = &kvm_init;
    driver.init_vmi_ptr = &kvm_init_vmi;
    driver.destroy_ptr = &kvm_destroy;
    driver.get_id_from_name_ptr = &kvm_get_id_from_name;
    driver.get_name_from_id_ptr = &kvm_get_name_from_id;
    driver.get_id_ptr = &kvm_get_id;
    driver.set_id_ptr = &kvm_set_id;
    driver.check_id_ptr = &kvm_check_id;
    driver.get_name_ptr = &kvm_get_name;
    driver.set_name_ptr = &kvm_set_name;
    driver.write_ptr = &kvm_write;
    driver.get_memsize_ptr = &kvm_get_memsize;
# ifndef ENABLE_KVM_LEGACY
    driver.request_page_fault_ptr = &kvm_request_page_fault;
    driver.get_tsc_info_ptr = &kvm_get_tsc_info;
# endif
    driver.get_vcpureg_ptr = &kvm_get_vcpureg;
# ifndef ENABLE_KVM_LEGACY
    driver.get_vcpuregs_ptr = &kvm_get_vcpuregs;
    driver.set_vcpureg_ptr = &kvm_set_vcpureg;
    driver.set_vcpuregs_ptr = &kvm_set_vcpuregs;
# endif
    driver.read_page_ptr = &kvm_read_page;
    driver.is_pv_ptr = &kvm_is_pv;
    driver.pause_vm_ptr = &kvm_pause_vm;
    driver.resume_vm_ptr = &kvm_resume_vm;
# ifndef ENABLE_KVM_LEGACY
    driver.request_page_fault_ptr = &kvm_request_page_fault;
    driver.get_tsc_info_ptr = &kvm_get_tsc_info;
    driver.get_vcpuregs_ptr = &kvm_get_vcpuregs;
    driver.set_vcpureg_ptr = &kvm_set_vcpureg;
    driver.set_vcpuregs_ptr = &kvm_set_vcpuregs;
# endif
    vmi->driver = driver;
    return VMI_SUCCESS;
}

#endif /* KVM_H */

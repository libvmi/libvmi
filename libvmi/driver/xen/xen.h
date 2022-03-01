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

#ifndef XEN_DRIVER_H
#define XEN_DRIVER_H

#if ENABLE_XEN_EVENTS == 1
#include "driver/xen/xen_events.h"
#endif

#ifdef HAVE_LIBXENSTORE
static const char RELEASE_TOKEN[] = "release";
static const char INTRODUCE_TOKEN[] = "introduce";
#endif

struct hvm_hw_cpu_xsave_46 {
    uint64_t xfeature_mask;        /* Ignored */
    uint64_t xcr0;                 /* Updated by XSETBV */
    uint64_t xcr0_accum;           /* Updated by XSETBV */
    struct {
        struct { char x[512]; } fpu_sse;

        struct hvm_hw_cpu_xsave_hdr_46 {
            uint64_t xstate_bv;         /* Updated by XRSTOR */
            uint64_t reserved[7];
        } xsave_hdr;                    /* The 64-byte header */
    } save_area;
};

struct hvm_hw_cpu_xsave_412 {
    uint64_t xfeature_mask;        /* Ignored */
    uint64_t xcr0;                 /* Updated by XSETBV */
    uint64_t xcr0_accum;           /* Updated by XSETBV */
    struct {
        struct { char x[512]; } fpu_sse;

        struct hvm_hw_cpu_xsave_hdr_412 {
            uint64_t xstate_bv;         /* Updated by XRSTOR */
            uint64_t xcomp_bv;          /* Updated by XRSTOR{C,S} */
            uint64_t reserved[6];
        } xsave_hdr;                    /* The 64-byte header */
    } save_area;
};

status_t xen_init(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);
status_t xen_init_vmi(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);
status_t xen_domainwatch_init(
    vmi_instance_t vmi,
    uint32_t init_flags);
void xen_destroy(
    vmi_instance_t vmi);
uint64_t xen_get_domainid_from_name(
    vmi_instance_t vmi,
    const char *name);
status_t xen_get_name_from_domainid(
    vmi_instance_t vmi,
    uint64_t domainid,
    char **name);
uint64_t xen_get_domainid_from_uuid(
    vmi_instance_t vmi,
    const char *uuid);
uint64_t xen_get_domainid(
    vmi_instance_t vmi);
void xen_set_domainid(
    vmi_instance_t vmi,
    uint64_t domainid);
status_t xen_check_domainid(
    vmi_instance_t vmi,
    uint64_t domainid);
status_t xen_get_domainname(
    vmi_instance_t vmi,
    char **name);
void xen_set_domainname(
    vmi_instance_t vmi,
    const char *name);
status_t xen_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address);
status_t xen_request_page_fault(
    vmi_instance_t vmi,
    unsigned long vcpu,
    uint64_t virtual_address,
    uint32_t error_code);
status_t xen_get_tsc_info(
    vmi_instance_t vmi,
    uint32_t *tsc_mode,
    uint64_t *elapsed_nsec,
    uint32_t *gtsc_khz,
    uint32_t *incarnation);
status_t xen_get_xsave_info(
    vmi_instance_t vmi,
    unsigned long vcpu,
    xsave_area_t *xsave_info);
status_t xen_get_vcpumtrr(
    vmi_instance_t vmi,
    mtrr_regs_t *hwMtrr,
    unsigned long vcpu);
status_t xen_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu);
status_t xen_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu);
status_t xen_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu);
status_t xen_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu);
void *xen_read_page(
    vmi_instance_t vmi,
    addr_t page);
void *xen_mmap_guest(
    vmi_instance_t vmi,
    unsigned long *pfns,
    unsigned int size);
status_t xen_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length);
int xen_is_pv(
    vmi_instance_t vmi);
status_t xen_test(
    uint64_t domainid,
    const char *name,
    uint64_t init_flags,
    void* init_data);
status_t xen_pause_vm(
    vmi_instance_t vmi);
status_t xen_resume_vm(
    vmi_instance_t vmi);
status_t xen_set_domain_debug_control(
    vmi_instance_t vmi,
    unsigned long vcpu,
    int enable);
status_t xen_set_access_required(
    vmi_instance_t vmi,
    bool required);
status_t xen_read_disk(
    vmi_instance_t vmi,
    const char *device_id,
    uint64_t offset,
    uint64_t count,
    void *buffer);
char **xen_get_disks(
    vmi_instance_t vmi,
    unsigned int *num);
status_t xen_disk_is_bootable(
    vmi_instance_t vmi,
    const char *device_id,
    bool *bootable);

static inline status_t
driver_xen_setup(vmi_instance_t vmi)
{
    driver_interface_t driver = { 0 };
    driver.initialized = true;
    driver.init_ptr = &xen_init;
    driver.init_vmi_ptr = &xen_init_vmi;
    driver.domainwatch_init_ptr = &xen_domainwatch_init;
    driver.destroy_ptr = &xen_destroy;
    driver.get_id_from_name_ptr = &xen_get_domainid_from_name;
    driver.get_name_from_id_ptr = &xen_get_name_from_domainid;
    driver.get_id_from_uuid_ptr = &xen_get_domainid_from_uuid;
    driver.get_id_ptr = &xen_get_domainid;
    driver.set_id_ptr = &xen_set_domainid;
    driver.check_id_ptr = &xen_check_domainid;
    driver.get_name_ptr = &xen_get_domainname;
    driver.set_name_ptr = &xen_set_domainname;
    driver.get_xsave_info_ptr = &xen_get_xsave_info;
    driver.get_memsize_ptr = &xen_get_memsize;
    driver.request_page_fault_ptr = &xen_request_page_fault;
    driver.get_tsc_info_ptr = &xen_get_tsc_info;
    driver.get_vcpumtrr_ptr = &xen_get_vcpumtrr;
    driver.get_vcpureg_ptr = &xen_get_vcpureg;
    driver.get_vcpuregs_ptr = &xen_get_vcpuregs;
    driver.set_vcpureg_ptr = &xen_set_vcpureg;
    driver.set_vcpuregs_ptr = &xen_set_vcpuregs;
    driver.read_page_ptr = &xen_read_page;
    driver.mmap_guest = &xen_mmap_guest;
    driver.write_ptr = &xen_write;
    driver.is_pv_ptr = &xen_is_pv;
    driver.pause_vm_ptr = &xen_pause_vm;
    driver.resume_vm_ptr = &xen_resume_vm;
    driver.set_access_required_ptr = &xen_set_access_required;
    driver.read_disk_ptr = &xen_read_disk;
    driver.get_disks_ptr = &xen_get_disks;
    driver.disk_is_bootable_ptr = &xen_disk_is_bootable;
    vmi->driver = driver;
    return VMI_SUCCESS;
}

#endif /* XEN_DRIVER_H */

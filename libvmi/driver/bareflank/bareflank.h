/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * Author: Tamas K Lengyel <lengyelt@ainfosec.com>
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

#ifndef BAREFLANK_DRIVER_H
#define BAREFLANK_DRIVER_H

status_t bareflank_test(
    uint64_t domainid,
    const char *name);
status_t bareflank_init(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);
status_t bareflank_init_vmi(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);
void bareflank_destroy(
    vmi_instance_t vmi);
void *bareflank_read_page(
    vmi_instance_t vmi,
    addr_t page);
status_t bareflank_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length);
status_t bareflank_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu);

status_t bareflank_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address);
status_t bareflank_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu);
status_t bareflank_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu);
status_t bareflank_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu);
void bareflank_set_id(
    vmi_instance_t vmi,
    uint64_t domainid);
void bareflank_set_name(
    vmi_instance_t vmi,
    const char *name);
uint64_t bareflank_get_domainid_from_name(
    vmi_instance_t vmi,
    const char* name);
status_t bareflank_get_name_from_domainid(
    vmi_instance_t vmi,
    uint64_t domainid,
    char** name);
status_t bareflank_pause_vm(
    vmi_instance_t vmi);
status_t bareflank_resume_vm(
    vmi_instance_t vmi);

static inline status_t
driver_bareflank_setup(vmi_instance_t vmi)
{
    driver_interface_t driver = { 0 };
    driver.initialized = true;
    driver.init_ptr = &bareflank_init;
    driver.init_vmi_ptr = &bareflank_init_vmi;
    driver.destroy_ptr = &bareflank_destroy;
    driver.get_id_from_name_ptr = &bareflank_get_domainid_from_name;
    driver.get_name_from_id_ptr = &bareflank_get_name_from_domainid;
    //driver.get_id_ptr = &xen_get_domainid;
    driver.set_id_ptr = &bareflank_set_id;
    //driver.check_id_ptr = &xen_check_domainid;
    //driver.get_name_ptr = &xen_get_domainname;
    driver.set_name_ptr = &bareflank_set_name;
    driver.get_memsize_ptr = &bareflank_get_memsize;
    driver.get_vcpureg_ptr = &bareflank_get_vcpureg;
    //driver.get_vcpuregs_ptr = &bareflank_get_vcpuregs;
    //driver.set_vcpureg_ptr = &bareflank_set_vcpureg;
    //driver.set_vcpuregs_ptr = &bareflank_set_vcpuregs;
    driver.read_page_ptr = &bareflank_read_page;

    driver.pause_vm_ptr = &bareflank_pause_vm;
    driver.resume_vm_ptr = &bareflank_resume_vm;

    driver.write_ptr = &bareflank_write;
    //driver.is_pv_ptr = &bareflank_is_pv;
    //driver.set_access_required_ptr = &xen_set_access_required;
    vmi->driver = driver;
    return VMI_SUCCESS;
}

#endif

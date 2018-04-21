/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel <tamas.lengyel@zentific.com>
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

#ifndef FILE_DRIVER_H
#define FILE_DRIVER_H

status_t file_init(
    vmi_instance_t vmi,
    uint32_t init_flags,
    void *init_data);
status_t file_init_vmi(
    vmi_instance_t vmi,
    uint32_t init_flags,
    void *init_data);
void file_destroy(
    vmi_instance_t vmi);
status_t file_get_name(
    vmi_instance_t vmi,
    char **name);
void file_set_name(
    vmi_instance_t vmi,
    const char *name);
status_t file_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address);
status_t file_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu);
void *file_read_page(
    vmi_instance_t vmi,
    addr_t page);
status_t file_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length);
int file_is_pv(
    vmi_instance_t vmi);
status_t file_test(
    uint64_t id,
    const char *name,
    uint64_t init_flags,
    void* init_data);
status_t file_pause_vm(
    vmi_instance_t vmi);
status_t file_resume_vm(
    vmi_instance_t vmi);

static inline status_t
driver_file_setup(vmi_instance_t vmi)
{
    driver_interface_t driver = { 0 };
    driver.initialized = true;
    driver.init_ptr = &file_init;
    driver.init_vmi_ptr = &file_init_vmi;
    driver.destroy_ptr = &file_destroy;
    driver.get_name_ptr = &file_get_name;
    driver.set_name_ptr = &file_set_name;
    driver.get_memsize_ptr = &file_get_memsize;
    driver.get_vcpureg_ptr = &file_get_vcpureg;
    driver.read_page_ptr = &file_read_page;
    driver.write_ptr = &file_write;
    driver.is_pv_ptr = &file_is_pv;
    driver.pause_vm_ptr = &file_pause_vm;
    driver.resume_vm_ptr = &file_resume_vm;
    vmi->driver = driver;
    return VMI_SUCCESS;
}

#endif /* FILE_DRIVER_H */

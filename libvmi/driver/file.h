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

typedef struct file_instance {

    FILE *fhandle;       /**< handle to the memory image file */

    int fd;              /**< file descriptor to the memory image file */

    char *filename;      /**< name of the file being accessed */

    void *map;           /**< memory mapped file */
} file_instance_t;

status_t file_init(
    vmi_instance_t vmi);
void file_destroy(
    vmi_instance_t vmi);
status_t file_get_name(
    vmi_instance_t vmi,
    char **name);
void file_set_name(
    vmi_instance_t vmi,
    char *name);
status_t file_get_memsize(
    vmi_instance_t vmi,
    unsigned long *size);
status_t file_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
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
    unsigned long id,
    char *name);
status_t file_pause_vm(
    vmi_instance_t vmi);
status_t file_resume_vm(
    vmi_instance_t vmi);

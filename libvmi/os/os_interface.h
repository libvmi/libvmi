/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
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

#ifndef OS_INTERFACE_H_
#define OS_INTERFACE_H_

#include "private.h"
#include "os/windows/windows.h"
#include "os/linux/linux.h"
#include "os/freebsd/freebsd.h"

typedef status_t (*os_get_offset_t)(vmi_instance_t vmi,
                                    const char* offset_name, addr_t *offset);

typedef status_t (*os_get_kernel_struct_offset_t)(vmi_instance_t vmi,
        const char* symbol, const char* member, addr_t *addr);

typedef status_t (*os_pgd_to_pid_t)(vmi_instance_t vmi, addr_t pgd, vmi_pid_t *pid);

typedef status_t (*os_pid_to_pgd_t)(vmi_instance_t vmi, vmi_pid_t pid, addr_t *dtb);

typedef status_t (*os_kernel_symbol_to_address_t)(vmi_instance_t instance,
        const char *symbol, addr_t *kernel_base_vaddr, addr_t *address);

typedef status_t (*os_user_symbol_to_rva_t)(vmi_instance_t instance,
        const access_context_t *ctx, const char *symbol, addr_t *rva);

typedef char* (*os_address_to_symbol_t)(vmi_instance_t vmi, addr_t address,
                                        const access_context_t *ctx);

typedef char* (*os_address_to_symbol_kaslr_t)(vmi_instance_t vmi, addr_t address,
        const access_context_t *ctx);

typedef unicode_string_t* (*os_read_unicode_struct_t)(vmi_instance_t vmi,
        const access_context_t *ctx);

typedef status_t (*os_teardown_t)(vmi_instance_t vmi);

typedef struct os_interface {
    os_get_kernel_struct_offset_t os_get_kernel_struct_offset;
    os_get_offset_t os_get_offset;
    os_pgd_to_pid_t os_pgd_to_pid;
    os_pid_to_pgd_t os_pid_to_pgd;
    os_kernel_symbol_to_address_t os_ksym2v;
    os_user_symbol_to_rva_t os_usym2rva;
    os_address_to_symbol_t os_v2sym;
    os_address_to_symbol_kaslr_t os_v2ksym;
    os_read_unicode_struct_t os_read_unicode_struct;
    os_teardown_t os_teardown;
} *os_interface_t;

/**
 * A util method to call os_teardown if it exists and free resources.
 *
 * @param vmi
 * @return
 */
status_t os_destroy(vmi_instance_t vmi);

#endif /* OS_INTERFACE_H_ */

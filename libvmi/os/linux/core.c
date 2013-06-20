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
#include "private.h"
#include "driver/interface.h"
#include "os/linux/linux.h"

status_t linux_init(vmi_instance_t vmi) {
    status_t ret = VMI_FAILURE;
    os_interface_t os_interface = NULL;

    if (vmi->cr3) {
        vmi->kpgd = vmi->cr3;
    } else if (VMI_SUCCESS
             == linux_system_map_symbol_to_address(vmi, "swapper_pg_dir",
                     NULL, &vmi->kpgd)) {
        dbprint("--got vaddr for swapper_pg_dir (0x%.16"PRIx64").\n",
                vmi->kpgd);
        if (driver_is_pv(vmi)) {
            vmi->kpgd = vmi_translate_kv2p(vmi,
                    vmi->kpgd);
            if (vmi_read_addr_pa(vmi, vmi->kpgd, &(vmi->kpgd))
                    == VMI_FAILURE) {
                errprint("Failed to get physical addr for kpgd.\n");
                goto _exit;
            }
        }
    } else if (vmi->cr3) {
        vmi->kpgd = vmi->cr3;
    } else {
        errprint("swapper_pg_dir not found and CR3 not set, exiting\n");
        goto _exit;
    }

    dbprint("**set vmi->kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    ret = linux_system_map_symbol_to_address(vmi, "init_task", NULL,
            &vmi->init_task);
    if (ret != VMI_SUCCESS) {
        errprint("VMI_ERROR: Could not get init_task from System.map\n");
        return ret;
    }

    os_interface = safe_malloc(sizeof(struct os_interface));
    bzero(os_interface, sizeof(struct os_interface));
    os_interface->os_get_offset = linux_get_offset;
    os_interface->os_pid_to_pgd = linux_pid_to_pgd;
    os_interface->os_pgd_to_pid = linux_pgd_to_pid;
    os_interface->os_ksym2v = linux_system_map_symbol_to_address;
    os_interface->os_usym2rva = NULL;
    os_interface->os_rva2sym = NULL;
    os_interface->os_teardown = linux_teardown;

    vmi->os_interface = os_interface;

    _exit: return ret;
}

unsigned long linux_get_offset(vmi_instance_t vmi, const char* offset_name) {
    const size_t max_length = 100;
    linux_instance_t linux_instance = vmi->os_data;

    if (linux_instance == NULL) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        return 0;
    }

    if (strncmp(offset_name, "linux_tasks", max_length) == 0) {
        return linux_instance->tasks_offset;
    } else if (strncmp(offset_name, "linux_mm", max_length) == 0) {
        return linux_instance->mm_offset;
    } else if (strncmp(offset_name, "linux_pid", max_length) == 0) {
        return linux_instance->pid_offset;
    } else if (strncmp(offset_name, "linux_name", max_length) == 0) {
        return linux_instance->name_offset;
    } else if (strncmp(offset_name, "linux_pgd", max_length) == 0) {
        return linux_instance->pgd_offset;
    } else {
        warnprint("Invalid offset name in linux_get_offset (%s).\n", offset_name);
        return 0;
    }
}

status_t linux_teardown(vmi_instance_t vmi) {
    linux_instance_t linux_instance = vmi->os_data;

    if (vmi->os_data == NULL) {
        return VMI_SUCCESS;
    }

    if (linux_instance->sysmap) {
        free(linux_instance->sysmap);
    }
    free(vmi->os_data);

    vmi->os_data = NULL;
    return VMI_SUCCESS;
}


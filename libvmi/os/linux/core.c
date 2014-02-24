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

void linux_read_config_ghashtable_entries(char* key, gpointer value,
        vmi_instance_t vmi);

status_t linux_init(vmi_instance_t vmi) {
    status_t ret = VMI_FAILURE;
    os_interface_t os_interface = NULL;

    if (vmi->config == NULL) {
        errprint("No config table found\n");
        return VMI_FAILURE;
    }

    if (vmi->os_data != NULL) {
        errprint("os data already initialized, reinitializing\n");
        free(vmi->os_data);
    }

    vmi->os_data = safe_malloc(sizeof(struct linux_instance));
    bzero(vmi->os_data, sizeof(struct linux_instance));
    linux_instance_t linux_instance = vmi->os_data;

    g_hash_table_foreach(vmi->config, (GHFunc)linux_read_config_ghashtable_entries, vmi);

    addr_t boundary = 0, phys_start = 0, virt_start = 0;

    if(vmi->page_mode == VMI_PM_IA32E) {
        linux_system_map_symbol_to_address(vmi, "phys_startup_64", NULL, &phys_start);
        linux_system_map_symbol_to_address(vmi, "startup_64", NULL, &virt_start);
    } else if (vmi->page_mode == VMI_PM_LEGACY || vmi->page_mode == VMI_PM_PAE) {
        linux_system_map_symbol_to_address(vmi, "phys_startup_32", NULL, &phys_start);
        linux_system_map_symbol_to_address(vmi, "startup_32", NULL, &virt_start);
    } else if (vmi->page_mode == VMI_PM_UNKNOWN) {
        ret = linux_system_map_symbol_to_address(vmi, "phys_startup_64", NULL, &phys_start);
        if(VMI_SUCCESS == ret) {
            linux_system_map_symbol_to_address(vmi, "startup_64", NULL, &virt_start);
            vmi->page_mode == VMI_PM_IA32E;
        } else {
            linux_system_map_symbol_to_address(vmi, "phys_startup_32", NULL, &phys_start);
            linux_system_map_symbol_to_address(vmi, "startup_32", NULL, &virt_start);
            vmi->page_mode == VMI_PM_PAE; // it's just a guess
        }
    }

    if(phys_start && virt_start && phys_start < virt_start) {
        boundary = virt_start - phys_start;
    } else {
        // Just guess the boundary
        boundary = 0xc0000000UL;
    }

    linux_instance->kernel_boundary = boundary;
    dbprint(VMI_DEBUG_MISC, "--got kernel boundary (0x%.16"PRIx64").\n", boundary);

    if(VMI_FAILURE == driver_get_vcpureg(vmi, &vmi->kpgd, CR3, 0)) {
        if (VMI_FAILURE == linux_system_map_symbol_to_address(vmi, "swapper_pg_dir", NULL, &vmi->kpgd)) {
            goto _exit;
        }

        dbprint(VMI_DEBUG_MISC, "--got vaddr for swapper_pg_dir (0x%.16"PRIx64").\n",
                vmi->kpgd);

        vmi->kpgd -= boundary;
    }

    if(!vmi->kpgd) {
        errprint("Failed to determine kpgd\n");
        goto _exit;
    }

    dbprint(VMI_DEBUG_MISC, "**set vmi->kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    // We check if the page mode is known
    // and if no arch interface has been setup yet we do it now
    if(VMI_PM_UNKNOWN == vmi->page_mode) {
        errprint("VMI_ERROR: Page mode is still unknown\n");
        goto _exit;
    } else if(!vmi->arch_interface) {
        if(VMI_FAILURE == arch_init(vmi)) {
            goto _exit;
        }
    }

    ret = linux_system_map_symbol_to_address(vmi, "init_task", NULL,
            &vmi->init_task);
    if (ret != VMI_SUCCESS) {
        errprint("Could not get init_task from System.map\n");
        goto _exit;
    }

    if(!vmi_pagetable_lookup(vmi, vmi->kpgd, vmi->init_task)) {
        errprint("Failed to translate init_task VA using the kpgd!\n");
        goto _exit;
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

    return VMI_SUCCESS;

    _exit:
    free(vmi->os_data);
    vmi->os_data = NULL;
    return VMI_FAILURE;
}

void linux_read_config_ghashtable_entries(char* key, gpointer value,
        vmi_instance_t vmi) {

    linux_instance_t linux_instance = vmi->os_data;

    if (strncmp(key, "sysmap", CONFIG_STR_LENGTH) == 0) {
        linux_instance->sysmap = strdup((char *)value);
        goto _done;
    }

    if (strncmp(key, "linux_tasks", CONFIG_STR_LENGTH) == 0) {
        linux_instance->tasks_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "linux_mm", CONFIG_STR_LENGTH) == 0) {
        linux_instance->mm_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "linux_pid", CONFIG_STR_LENGTH) == 0) {
        linux_instance->pid_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "linux_name", CONFIG_STR_LENGTH) == 0) {
        linux_instance->name_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "linux_pgd", CONFIG_STR_LENGTH) == 0) {
        linux_instance->pgd_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "ostype", CONFIG_STR_LENGTH) == 0 || strncmp(key, "os_type", CONFIG_STR_LENGTH) == 0) {
        goto _done;
    }

    if (strncmp(key, "name", CONFIG_STR_LENGTH) == 0) {
        goto _done;
    }

    if (strncmp(key, "domid", CONFIG_STR_LENGTH) == 0) {
        goto _done;
    }

    warnprint("Invalid offset %s given for Linux target\n", key);

    _done: return;
}

uint64_t linux_get_offset(vmi_instance_t vmi, const char* offset_name) {
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


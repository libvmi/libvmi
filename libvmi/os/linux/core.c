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

#include "private.h"
#include "config/config_parser.h"
#include "driver/driver_wrapper.h"
#include "os/linux/linux.h"

void linux_read_config_ghashtable_entries(char* key, gpointer value,
        vmi_instance_t vmi);

static status_t linux_filemode_32bit_init(vmi_instance_t vmi,
                                          addr_t swapper_pg_dir,
                                          addr_t boundary,
                                          addr_t pa, addr_t va)
{
    vmi->page_mode = VMI_PM_LEGACY;
    if (VMI_SUCCESS == arch_init(vmi)) {
        if (pa == vmi_pagetable_lookup(vmi, swapper_pg_dir - boundary, va)) {
            vmi->kpgd = swapper_pg_dir - boundary;
            return VMI_SUCCESS;
        }
    }

    vmi->page_mode = VMI_PM_PAE;
    if (VMI_SUCCESS == arch_init(vmi)) {
        if (pa == vmi_pagetable_lookup(vmi, swapper_pg_dir - boundary, va)) {
            vmi->kpgd = swapper_pg_dir - boundary;
            return VMI_SUCCESS;
        }
    }

    vmi->page_mode = VMI_PM_AARCH32;
    if (VMI_SUCCESS == arch_init(vmi)) {
        if (pa == vmi_pagetable_lookup(vmi, swapper_pg_dir - boundary, va)) {
            vmi->kpgd = swapper_pg_dir - boundary;
            return VMI_SUCCESS;
        }
    }

    return VMI_FAILURE;
}

static status_t linux_filemode_init(vmi_instance_t vmi)
{
    status_t rc;
    addr_t swapper_pg_dir = 0, init_level4_pgt = 0;
    addr_t boundary = 0, phys_start = 0, virt_start = 0;

    switch (vmi->page_mode)
    {
    case VMI_PM_AARCH64:
    case VMI_PM_IA32E:
        linux_symbol_to_address(vmi, "phys_startup_64", NULL, &phys_start);
        linux_symbol_to_address(vmi, "startup_64", NULL, &virt_start);
        break;
    case VMI_PM_AARCH32:
    case VMI_PM_LEGACY:
    case VMI_PM_PAE:
        linux_symbol_to_address(vmi, "phys_startup_32", NULL, &phys_start);
        linux_symbol_to_address(vmi, "startup_32", NULL, &virt_start);
        break;
    case VMI_PM_UNKNOWN:
        linux_symbol_to_address(vmi, "phys_startup_64", NULL, &phys_start);
        linux_symbol_to_address(vmi, "startup_64", NULL, &virt_start);

        if (phys_start && virt_start) break;
        phys_start = virt_start = 0;

        linux_symbol_to_address(vmi, "phys_startup_32", NULL, &phys_start);
        linux_symbol_to_address(vmi, "startup_32", NULL, &virt_start);
        break;
    }

    virt_start = canonical_addr(virt_start);

    if(phys_start && virt_start && phys_start < virt_start) {
        boundary = virt_start - phys_start;
        dbprint(VMI_DEBUG_MISC, "--got kernel boundary (0x%.16"PRIx64").\n", boundary);
    }

    rc = linux_symbol_to_address(vmi, "swapper_pg_dir", NULL, &swapper_pg_dir);

    if (VMI_SUCCESS == rc) {

        dbprint(VMI_DEBUG_MISC, "--got vaddr for swapper_pg_dir (0x%.16"PRIx64").\n",
                swapper_pg_dir);

        swapper_pg_dir = canonical_addr(swapper_pg_dir);

        /* We don't know if VMI_PM_LEGACY, VMI_PM_PAE or VMI_PM_AARCH32 yet
         * so we do some heuristics below. */
        if (boundary)
        {
        rc = linux_filemode_32bit_init(vmi, swapper_pg_dir, boundary,
                                       phys_start, virt_start);
        if (VMI_SUCCESS == rc)
            return rc;
        }

        /*
         * So we have a swapper but don't know the physical page of it.
         * We will make some educated guesses now.
         */
        boundary = 0xC0000000;
        dbprint(VMI_DEBUG_MISC, "--trying boundary 0x%.16"PRIx64".\n",
                boundary);
        rc = linux_filemode_32bit_init(vmi, swapper_pg_dir, boundary,
                                       swapper_pg_dir-boundary, swapper_pg_dir);
        if (VMI_SUCCESS == rc)
        {
            return rc;
        }

        boundary = 0x80000000;
        dbprint(VMI_DEBUG_MISC, "--trying boundary 0x%.16"PRIx64".\n",
                boundary);
        rc = linux_filemode_32bit_init(vmi, swapper_pg_dir, boundary,
                                       swapper_pg_dir-boundary, swapper_pg_dir);
        if (VMI_SUCCESS == rc)
        {
        return rc;
        }

        boundary = 0x40000000;
        dbprint(VMI_DEBUG_MISC, "--trying boundary 0x%.16"PRIx64".\n",
            boundary);
        rc = linux_filemode_32bit_init(vmi, swapper_pg_dir, boundary,
                                       swapper_pg_dir-boundary, swapper_pg_dir);
        if (VMI_SUCCESS == rc)
        {
            return rc;
        }

        return VMI_FAILURE;
    }

    rc = linux_symbol_to_address(vmi, "init_level4_pgt", NULL, &init_level4_pgt);
    if (rc == VMI_SUCCESS) {

        dbprint(VMI_DEBUG_MISC, "--got vaddr for init_level4_pgt (0x%.16"PRIx64").\n",
                init_level4_pgt);

        init_level4_pgt = canonical_addr(init_level4_pgt);

        if (boundary) {
            vmi->page_mode = VMI_PM_IA32E;
            if (VMI_SUCCESS == arch_init(vmi)) {
                if (phys_start == vmi_pagetable_lookup(vmi, init_level4_pgt - boundary, virt_start)) {
                    vmi->kpgd = init_level4_pgt - boundary;
                    return VMI_SUCCESS;
                }
            }
        }
    }

    return VMI_FAILURE;
}

static status_t init_from_rekall_profile(vmi_instance_t vmi) {

    status_t ret = VMI_FAILURE;
    linux_instance_t linux_instance = vmi->os_data;

    if(!linux_instance->tasks_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(linux_instance->rekall_profile, "task_struct", "tasks", &linux_instance->tasks_offset)) {
            goto done;
        }
    }
    if(!linux_instance->mm_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(linux_instance->rekall_profile, "task_struct", "mm", &linux_instance->mm_offset)) {
            goto done;
        }
    }
    if(!linux_instance->pid_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(linux_instance->rekall_profile, "task_struct", "pid", &linux_instance->pid_offset)) {
            goto done;
        }
    }
    if(!linux_instance->name_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(linux_instance->rekall_profile, "task_struct", "comm", &linux_instance->name_offset)) {
            goto done;
        }
    }
    if(!linux_instance->pgd_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(linux_instance->rekall_profile, "mm_struct", "pgd", &linux_instance->pgd_offset)) {
            goto done;
        }
    }
    if(!vmi->init_task) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(linux_instance->rekall_profile, "init_task", NULL, &vmi->init_task)) {
            goto done;
        }
    }

    ret = VMI_SUCCESS;

done: return ret;
}

status_t linux_init(vmi_instance_t vmi) {

    status_t rc;
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

    if(linux_instance->rekall_profile)
        rc = init_from_rekall_profile(vmi);
    else
        rc = linux_symbol_to_address(vmi, "init_task", NULL, &vmi->init_task);

    if (VMI_FAILURE == rc) {
        errprint("Could not get init_task from Rekall profile or System.map\n");
        goto _exit;
    }

    vmi->init_task = canonical_addr(vmi->init_task);

#if defined(ARM32) || defined(ARM64)
    rc = driver_get_vcpureg(vmi, &vmi->kpgd, TTBR1, 0);
#elif defined(I386) || defined(X86_64)
    rc = driver_get_vcpureg(vmi, &vmi->kpgd, CR3, 0);
#endif

    /*
     * The driver failed to get us a pagetable.
     * As a fall-back, try to init using heuristics.
     * This path is taken in FILE mode as well.
     */
    if (VMI_FAILURE == rc)
        if (VMI_FAILURE == linux_filemode_init(vmi))
            goto _exit;

    dbprint(VMI_DEBUG_MISC, "**set vmi->kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    os_interface = safe_malloc(sizeof(struct os_interface));
    bzero(os_interface, sizeof(struct os_interface));
    os_interface->os_get_offset = linux_get_offset;
    os_interface->os_pid_to_pgd = linux_pid_to_pgd;
    os_interface->os_pgd_to_pid = linux_pgd_to_pid;
    os_interface->os_ksym2v = linux_symbol_to_address;
    os_interface->os_usym2rva = NULL;
    os_interface->os_v2sym = linux_system_map_address_to_symbol;
    os_interface->os_read_unicode_struct = NULL;
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

    if (strncmp(key, "rekall_profile", CONFIG_STR_LENGTH) == 0) {
        linux_instance->rekall_profile = strdup((char *)value);
        goto _done;
    }

    if (strncmp(key, "linux_tasks", CONFIG_STR_LENGTH) == 0) {
        linux_instance->tasks_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "linux_mm", CONFIG_STR_LENGTH) == 0) {
        linux_instance->mm_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "linux_pid", CONFIG_STR_LENGTH) == 0) {
        linux_instance->pid_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "linux_name", CONFIG_STR_LENGTH) == 0) {
        linux_instance->name_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "linux_pgd", CONFIG_STR_LENGTH) == 0) {
        linux_instance->pgd_offset = *(addr_t *)value;
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

    if (strncmp(key, "physoffset", CONFIG_STR_LENGTH) == 0) {
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

    free(linux_instance->sysmap);
    free(linux_instance->rekall_profile);
    free(vmi->os_data);

    vmi->os_data = NULL;
    return VMI_SUCCESS;
}


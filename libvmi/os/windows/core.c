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
#include "peparse.h"
#include "os/windows/windows.h"

addr_t windows_find_eprocess(vmi_instance_t instance, char *name);

addr_t
get_ntoskrnl_base(
    vmi_instance_t vmi,
    addr_t page_paddr)
{
    uint8_t page[VMI_PS_4KB];
    addr_t ret = 0;
    int i = 0;

    for(; page_paddr + VMI_PS_4KB < vmi->size ; page_paddr += VMI_PS_4KB) {

        uint8_t page[VMI_PS_4KB];
        status_t rc = peparse_get_image_phys(vmi, page_paddr, VMI_PS_4KB, page);
        if(VMI_FAILURE == rc) {
            continue;
        }

        struct pe_header *pe_header = NULL;
        struct dos_header *dos_header = NULL;
        void *optional_pe_header = NULL;
        uint16_t optional_header_type = 0;
        struct export_table et;

        peparse_assign_headers(page, &dos_header, &pe_header, &optional_header_type, &optional_pe_header, NULL, NULL);
        addr_t export_header_offset =
            peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_EXPORT, &optional_header_type, optional_pe_header, NULL, NULL);

        if(!export_header_offset || page_paddr + export_header_offset > vmi->size)
            continue;

        uint32_t nbytes = vmi_read_pa(vmi, page_paddr + export_header_offset, &et, sizeof(struct export_table));
        if(nbytes == sizeof(struct export_table) && !(et.export_flags || !et.name) ) {

            if(page_paddr + et.name + 12 > vmi->size) {
                continue;
            }

            unsigned char name[13] = {0};
            vmi_read_pa(vmi, page_paddr + et.name, name, 12);
            if(!strcmp("ntoskrnl.exe", name)) {
                ret = page_paddr;
                break;
            }
        } else {
            continue;
        }
    }

    return ret;
}

static status_t
find_page_mode(
    vmi_instance_t vmi)
{

    status_t ret = VMI_FAILURE;
    windows_instance_t windows = vmi->os_data;

    dbprint(VMI_DEBUG_MISC, "--trying VMI_PM_LEGACY\n");
    vmi->page_mode = VMI_PM_LEGACY;

    if (VMI_SUCCESS == arch_init(vmi)) {
        if (windows->ntoskrnl == vmi_pagetable_lookup(vmi, vmi->kpgd, windows->ntoskrnl_va)) {
            goto found_pm;
        }
    }

    dbprint(VMI_DEBUG_MISC, "--trying VMI_PM_PAE\n");
    vmi->page_mode = VMI_PM_PAE;

    if (VMI_SUCCESS == arch_init(vmi)) {
        if (windows->ntoskrnl == vmi_pagetable_lookup(vmi, vmi->kpgd, windows->ntoskrnl_va)) {
            goto found_pm;
        }
    }

    dbprint(VMI_DEBUG_MISC, "--trying VMI_PM_IA32E\n");
    vmi->page_mode = VMI_PM_IA32E;

    if (VMI_SUCCESS == arch_init(vmi)) {
        if (windows->ntoskrnl == vmi_pagetable_lookup(vmi, vmi->kpgd, windows->ntoskrnl_va)) {
            goto found_pm;
        }
    }

    goto done;

    found_pm:
        ret = VMI_SUCCESS;

    done: return ret;
}

/* Tries to find the kernel page directory by doing an exhaustive search
 * through the memory space for the System process.  The page directory
 * location is then pulled from this eprocess struct.
 */
static status_t
get_kpgd_method2(
    vmi_instance_t vmi)
{
    addr_t sysproc = 0;
    windows_instance_t windows = NULL;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No OS data initialized\n");
        return VMI_FAILURE;
    }

    windows = vmi->os_data;
    sysproc = windows->sysproc;

    /* get address for System process */
    if (!sysproc) {
        if ((sysproc = windows_find_eprocess(vmi, "Idle")) == 0) {
            dbprint(VMI_DEBUG_MISC, "--failed to find Idle process.\n");
            goto error_exit;
        }
        printf("LibVMI Suggestion: set win_sysproc=0x%"PRIx64" in libvmi.conf for faster startup.\n",
             sysproc);
    }
    dbprint(VMI_DEBUG_MISC, "--got PA to PsInitialSystemProcess (0x%.16"PRIx64").\n",
            sysproc);

    /* get address for page directory (from system process) */
    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                         sysproc +
                         windows->pdbase_offset,
                         &vmi->kpgd)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve PD for Idle process\n");
        goto error_exit;
    }

    if (!vmi->kpgd) {
        dbprint(VMI_DEBUG_MISC, "--kpgd was zero\n");
        goto error_exit;
    }
    dbprint(VMI_DEBUG_MISC, "**set kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                     sysproc + windows->tasks_offset,
                     &vmi->init_task)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve address of Idle process\n");
        goto error_exit;
    }
    vmi->init_task -= windows->tasks_offset;
    dbprint(VMI_DEBUG_MISC, "**set init_task (0x%.16"PRIx64").\n", vmi->init_task);

    return VMI_SUCCESS;

error_exit:
    return VMI_FAILURE;
}

addr_t
windows_find_cr3(
    vmi_instance_t vmi)
{
    get_kpgd_method2(vmi);
    return vmi->kpgd;
}

/* Tries to find the kernel page directory using the RVA value for
 * PSInitialSystemProcess and the ntoskrnl value to lookup the System
 * process, and the extract the page directory location from this
 * eprocess struct.
 */
static status_t
get_kpgd_method1(
    vmi_instance_t vmi)
{
    addr_t sysproc = 0;
    windows_instance_t windows = NULL;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No OS data initialized\n");
        return VMI_FAILURE;
    }

    windows = vmi->os_data;

    if (VMI_FAILURE ==
        vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &sysproc)) {
        dbprint(VMI_DEBUG_MISC, "--failed to read pointer for system process\n");
        goto error_exit;
    }
    sysproc = vmi_translate_kv2p(vmi, sysproc);
    dbprint(VMI_DEBUG_MISC, "--got PA to PsInitialSystemProcess (0x%.16"PRIx64").\n",
            sysproc);

    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                         sysproc +
                         windows->pdbase_offset,
                         &vmi->kpgd)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve pointer for system process\n");
        goto error_exit;
    }

    if (!vmi->kpgd) {
        dbprint(VMI_DEBUG_MISC, "--kpgd was zero\n");
        goto error_exit;
    }
    dbprint(VMI_DEBUG_MISC, "**set kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                     sysproc + windows->tasks_offset,
                     &vmi->init_task)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve address of Idle process\n");
        goto error_exit;
    }
    vmi->init_task -= windows->tasks_offset;
    dbprint(VMI_DEBUG_MISC, "**set init_task (0x%.16"PRIx64").\n", vmi->init_task);

    return VMI_SUCCESS;

error_exit:
    return VMI_FAILURE;
}

static status_t
get_kpgd_method0(
    vmi_instance_t vmi)
{
    addr_t sysproc = 0;
    windows_instance_t windows = NULL;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No OS data initialized\n");
        return VMI_FAILURE;
    }

    windows = vmi->os_data;

    if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &sysproc)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve PsActiveProcessHead\n");
        goto error_exit;
    }
    if (VMI_FAILURE == vmi_read_addr_va(vmi, sysproc, 0, &sysproc)) {
        dbprint(VMI_DEBUG_MISC, "--failed to translate PsActiveProcessHead\n");
        goto error_exit;
    }
    sysproc = vmi_translate_kv2p(vmi, sysproc) - windows->tasks_offset;
    dbprint(VMI_DEBUG_MISC, "--got PA to PsActiveProcessHead (0x%.16"PRIx64").\n", sysproc);

    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                         sysproc +
                         windows->pdbase_offset,
                         &vmi->kpgd)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve pointer for system process\n");
        goto error_exit;
    }

    if (!vmi->kpgd) {
        dbprint(VMI_DEBUG_MISC, "--kpgd was zero\n");
        goto error_exit;
    }
    dbprint(VMI_DEBUG_MISC, "**set kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                     sysproc + windows->tasks_offset,
                     &vmi->init_task)){
        dbprint(VMI_DEBUG_MISC, "--failed to resolve address of Idle process\n");
        goto error_exit;
    }
    vmi->init_task -= windows->tasks_offset;
    dbprint(VMI_DEBUG_MISC, "**set init_task (0x%.16"PRIx64").\n", vmi->init_task);

    return VMI_SUCCESS;

error_exit:
    return VMI_FAILURE;
}

uint64_t windows_get_offset(vmi_instance_t vmi, const char* offset_name) {
    const size_t max_length = 100;
    windows_instance_t windows = vmi->os_data;

    if (windows == NULL) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        return 0;
    }

    if (strncmp(offset_name, "win_tasks", max_length) == 0) {
        return windows->tasks_offset;
    } else if (strncmp(offset_name, "win_pdbase", max_length) == 0) {
        return windows->pdbase_offset;
    } else if (strncmp(offset_name, "win_pid", max_length) == 0) {
        return windows->pid_offset;
    } else if (strncmp(offset_name, "win_pname", max_length) == 0) {
        if (windows->pname_offset == 0) {
            windows->pname_offset = find_pname_offset(vmi,
                    NULL );
            if (windows->pname_offset == 0) {
                dbprint(VMI_DEBUG_MISC, "--failed to find pname_offset\n");
                return 0;
            }
        }
        return windows->pname_offset;
    } else {
        warnprint("Invalid offset name in windows_get_offset (%s).\n",
                offset_name);
        return 0;
    }
}

void windows_read_config_ghashtable_entries(char* key, gpointer value,
        vmi_instance_t vmi) {

    windows_instance_t windows_instance = vmi->os_data;

    if (strncmp(key, "win_ntoskrnl", CONFIG_STR_LENGTH) == 0) {
        windows_instance->ntoskrnl = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_tasks", CONFIG_STR_LENGTH) == 0) {
        windows_instance->tasks_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_pdbase", CONFIG_STR_LENGTH) == 0) {
        windows_instance->pdbase_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_pid", CONFIG_STR_LENGTH) == 0) {
        windows_instance->pid_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_pname", CONFIG_STR_LENGTH) == 0) {
        windows_instance->pname_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_kdvb", CONFIG_STR_LENGTH) == 0) {
        windows_instance->kdbg_va = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_sysproc", CONFIG_STR_LENGTH) == 0) {
        windows_instance->sysproc = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_kpcr", CONFIG_STR_LENGTH) == 0) {
        windows_instance->kpcr_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_kdbg", CONFIG_STR_LENGTH) == 0) {
        windows_instance->kdbg_offset = *(addr_t *)value;
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

    warnprint("Invalid offset \"%s\" given for Windows target\n", key);

    _done: return;
}


status_t
windows_init(
    vmi_instance_t vmi)
{
    status_t status = VMI_FAILURE;
    windows_instance_t windows = NULL;
    os_interface_t os_interface = NULL;

    if (vmi->config == NULL) {
        errprint("VMI_ERROR: No config table found\n");
        return VMI_FAILURE;
    }

    if (vmi->os_data != NULL) {
        errprint("VMI_ERROR: os data already initialized, resetting\n");
    } else {
        vmi->os_data = safe_malloc(sizeof(struct windows_instance));
    }

    bzero(vmi->os_data, sizeof(struct windows_instance));
    windows = vmi->os_data;
    windows->version = VMI_OS_WINDOWS_UNKNOWN;

    g_hash_table_foreach(vmi->config, (GHFunc)windows_read_config_ghashtable_entries, vmi);

    /* Need to provide this functions so that find_page_mode will work */
    os_interface = safe_malloc(sizeof(struct os_interface));
    bzero(os_interface, sizeof(struct os_interface));
    os_interface->os_get_offset = windows_get_offset;
    os_interface->os_pid_to_pgd = windows_pid_to_pgd;
    os_interface->os_pgd_to_pid = windows_pgd_to_pid;
    os_interface->os_ksym2v = windows_kernel_symbol_to_address;
    os_interface->os_usym2rva = windows_export_to_rva;
    os_interface->os_rva2sym = windows_rva_to_export;
    os_interface->os_teardown = NULL;

    vmi->os_interface = os_interface;

    if (VMI_PM_UNKNOWN == vmi->page_mode) {
        if(VMI_FAILURE == get_kpgd_method2(vmi)) {
          errprint("Could not get kpgd, will not be able to determine page mode\n");
          goto error_exit;
        }

        if(VMI_FAILURE == init_kdbg(vmi)) {
            goto error_exit;
        }

        if (VMI_FAILURE == find_page_mode(vmi)) {
            errprint("Failed to find correct page mode.\n");
            goto error_exit;
        }
    } else if(VMI_FAILURE == init_kdbg(vmi)) {
        goto error_exit;
    }

    if (vmi->kpgd) {
        /* This can happen for file because find_cr3() is called and this
         * is set via get_kpgd_method2() */
        status = VMI_SUCCESS;
    } else
    if (VMI_SUCCESS == get_kpgd_method0(vmi)) {
        dbprint(VMI_DEBUG_MISC, "--kpgd method0 success\n");
        status = VMI_SUCCESS;
    } else
    if (VMI_SUCCESS == get_kpgd_method1(vmi)) {
        dbprint(VMI_DEBUG_MISC, "--kpgd method1 success\n");
        status = VMI_SUCCESS;
    } else
    if (VMI_SUCCESS == get_kpgd_method2(vmi)) {
        dbprint(VMI_DEBUG_MISC, "--kpgd method2 success\n");
        status = VMI_SUCCESS;
    } else {
        errprint("Failed to find kernel page directory.\n");
        goto error_exit;
    }

    return status;

error_exit:
    free(vmi->os_interface);
    vmi->os_interface = NULL;
    return VMI_FAILURE;
}

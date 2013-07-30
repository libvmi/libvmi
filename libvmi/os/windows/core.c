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
    vmi_instance_t vmi)
{
#define MAX_HEADER_BYTES 1024
    uint8_t image[MAX_HEADER_BYTES];
    size_t nbytes = 0;
    addr_t paddr = 0;
    int i = 0;

    while (paddr < vmi_get_memsize(vmi)) {
        nbytes = vmi_read_pa(vmi, paddr, image, MAX_HEADER_BYTES);
        if (MAX_HEADER_BYTES != nbytes) {
            continue;
        }
        if (VMI_SUCCESS == peparse_validate_pe_image(image, MAX_HEADER_BYTES)) {
            dbprint("--FOUND KERNEL at paddr=0x%"PRIx64"\n", paddr);
            goto normal_exit;
        }
        paddr += vmi->page_size;
    }

error_exit:
    dbprint("--get_ntoskrnl_base failed\n");
    return 0;
normal_exit:
    return paddr;
}

static status_t
find_page_mode(
    vmi_instance_t vmi)
{
    addr_t proc = 0;

    //get_ntoskrnl_base(vmi);

    //TODO This works well for 32-bit snapshots, but it is way too slow for 64-bit.

    dbprint("--trying VMI_PM_LEGACY\n");
    vmi->page_mode = VMI_PM_LEGACY;
    if (VMI_SUCCESS == vmi_read_addr_ksym(vmi, "KernBase", &proc)) {
        goto found_pm;
    }
    v2p_cache_flush(vmi);

    dbprint("--trying VMI_PM_PAE\n");
    vmi->page_mode = VMI_PM_PAE;
    if (VMI_SUCCESS == vmi_read_addr_ksym(vmi, "KernBase", &proc)) {
        goto found_pm;
    }
    v2p_cache_flush(vmi);

    dbprint("--trying VMI_PM_IA32E\n");
    vmi->page_mode = VMI_PM_IA32E;
    if (VMI_SUCCESS == vmi_read_addr_ksym(vmi, "KernBase", &proc)) {
        goto found_pm;
    }

    // KernBase was NOT found ////////////////
    v2p_cache_flush(vmi);
    return VMI_FAILURE;

found_pm:
    return VMI_SUCCESS;
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
        if ((sysproc = windows_find_eprocess(vmi, "System")) == 0) {
            dbprint("--failed to find System process.\n");
            goto error_exit;
        }
        printf
            ("LibVMI Suggestion: set win_sysproc=0x%"PRIx64" in libvmi.conf for faster startup.\n",
             sysproc);
    }
    dbprint("--got PA to PsInititalSystemProcess (0x%.16"PRIx64").\n",
            sysproc);

    /* get address for page directory (from system process) */
    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                         sysproc +
                         windows->pdbase_offset,
                         &vmi->kpgd)) {
        dbprint("--failed to resolve PD for Idle process\n");
        goto error_exit;
    }

    if (!vmi->kpgd) {
        dbprint("--kpgd was zero\n");
        goto error_exit;
    }
    dbprint("**set kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    if (VMI_FAILURE == 
        vmi_read_addr_pa(vmi,
                     sysproc + windows->tasks_offset,
                     &vmi->init_task)) {
        dbprint("--failed to resolve address of Idle process\n");
        goto error_exit;
    }
    vmi->init_task -= windows->tasks_offset;
    dbprint("**set init_task (0x%.16"PRIx64").\n", vmi->init_task);

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
        dbprint("--failed to read pointer for system process\n");
        goto error_exit;
    }
    sysproc = vmi_translate_kv2p(vmi, sysproc);
    dbprint("--got PA to PsInititalSystemProcess (0x%.16"PRIx64").\n",
            sysproc);

    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                         sysproc +
                         windows->pdbase_offset,
                         &vmi->kpgd)) {
        dbprint("--failed to resolve pointer for system process\n");
        goto error_exit;
    }

    if (!vmi->kpgd) {
        dbprint("--kpgd was zero\n");
        goto error_exit;
    }
    dbprint("**set kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    if (VMI_FAILURE == 
        vmi_read_addr_pa(vmi,
                     sysproc + windows->tasks_offset,
                     &vmi->init_task)) {
        dbprint("--failed to resolve address of Idle process\n");
        goto error_exit;
    }
    vmi->init_task -= windows->tasks_offset;
    dbprint("**set init_task (0x%.16"PRIx64").\n", vmi->init_task);

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

    if (VMI_FAILURE ==
        windows_kernel_symbol_to_address(vmi, "PsActiveProcessHead",
                                  NULL,
                                  &sysproc)) {
        dbprint("--failed to resolve PsActiveProcessHead\n");
        goto error_exit;
    }
    if (VMI_FAILURE == vmi_read_addr_va(vmi, sysproc, 0, &sysproc)) {
        dbprint("--failed to translate PsActiveProcessHead\n");
        goto error_exit;
    }
    sysproc =
        vmi_translate_kv2p(vmi,
                           sysproc) -
        windows->tasks_offset;
    dbprint("--got PA to PsActiveProcessHead (0x%.16"PRIx64").\n", sysproc);

    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                         sysproc +
                         windows->pdbase_offset,
                         &vmi->kpgd)) {
        dbprint("--failed to resolve pointer for system process\n");
        goto error_exit;
    }

    if (!vmi->kpgd) {
        dbprint("--kpgd was zero\n");
        goto error_exit;
    }
    dbprint("**set kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    if (VMI_FAILURE == 
        vmi_read_addr_pa(vmi,
                     sysproc + windows->tasks_offset,
                     &vmi->init_task)){
        dbprint("--failed to resolve address of Idle process\n");
        goto error_exit;
    }
    vmi->init_task -= windows->tasks_offset;
    dbprint("**set init_task (0x%.16"PRIx64").\n", vmi->init_task);

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
                dbprint("--failed to find pname_offset\n");
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
        windows_instance->kdversion_block = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_sysproc", CONFIG_STR_LENGTH) == 0) {
        windows_instance->sysproc = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "ostype", CONFIG_STR_LENGTH) == 0) {
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
        errprint("VMI_ERROR: os data already initialized, reinitializing\n");
        free(vmi->os_data);
    }

    vmi->os_data = safe_malloc(sizeof(struct windows_instance));
    bzero(vmi->os_data, sizeof(struct windows_instance));
    windows = vmi->os_data;

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

    /* get base address for kernel image in memory */
    if (VMI_PM_UNKNOWN == vmi->page_mode) {
        if (!vmi->kpgd) {
            status = get_kpgd_method2(vmi);
            if (status == VMI_FAILURE) {
                errprint("Could not get_kpgd, will not be able to determine page mode\n");
                goto error_exit;
            }
        }

        if (VMI_FAILURE == find_page_mode(vmi)) {
            errprint("Failed to find correct page mode.\n");
            goto error_exit;
        }
    }


    if (VMI_FAILURE ==
        windows_kernel_symbol_to_address(vmi, "KernBase",
                                  NULL,
                                  &windows->ntoskrnl_va)) {
        errprint("Address translation failure.\n");
        goto error_exit;
    }

    dbprint("**ntoskrnl @ VA 0x%.16"PRIx64".\n",
            windows->ntoskrnl_va);

    windows->ntoskrnl =
        vmi_translate_kv2p(vmi, windows->ntoskrnl_va);
    dbprint("**set ntoskrnl (0x%.16"PRIx64").\n",
            windows->ntoskrnl);

    if (vmi->kpgd) {
        /* This can happen for file because find_cr3() is called and this
         * is set via get_kpgd_method2() /
         */
        goto found_kpgd;
    }

    /* get the kernel page directory location */
    if (VMI_SUCCESS == get_kpgd_method0(vmi)) {
        dbprint("--kpgd method0 success\n");
        goto found_kpgd;
    }
    if (VMI_SUCCESS == get_kpgd_method1(vmi)) {
        dbprint("--kpgd method1 success\n");
        goto found_kpgd;
    }
    if (VMI_SUCCESS == get_kpgd_method2(vmi)) {
        dbprint("--kpgd method1 success\n");
        goto found_kpgd;
    }
    /* all methods exhausted */
    errprint("Failed to find kernel page directory.\n");
    goto error_exit;

found_kpgd:
    return VMI_SUCCESS;
error_exit:
    free(vmi->os_interface);
    vmi->os_interface = NULL;
    return VMI_FAILURE;
}

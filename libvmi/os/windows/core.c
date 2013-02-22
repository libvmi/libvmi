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
#include "peparse.h"
#include "private.h"
#include "kernel.h"

#define MAX_HEADER_BYTES 1024

addr_t
get_ntoskrnl_base(
    vmi_instance_t vmi)
{

    uint8_t image[MAX_HEADER_BYTES];
    size_t nbytes = 0;
    addr_t paddr = 0;
    int i = 0;

    while (paddr < vmi_get_memsize(vmi)) {
        nbytes = vmi_read_pa(vmi, paddr, image, MAX_HEADER_BYTES);
        if (MAX_HEADER_BYTES != nbytes) {
            continue;
        }
        if (VMI_SUCCESS == peparse_validate_pe_image(image, MAX_HEADER_BYTES)
            &&
            VMI_SUCCESS == is_WINDOWS_KERNEL(vmi, paddr, image)
        ) {
            dbprint("--FOUND KERNEL at paddr=0x%llx\n", paddr);
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


/*
 * Search for the kernel image manually and determine the page mode
 * based on the kernel's PE optional header and kernel name
 */
status_t
find_page_mode2(
    vmi_instance_t vmi)
{

    uint8_t pe[MAX_HEADER_BYTES];
    addr_t kernel_base_p=get_ntoskrnl_base(vmi);

    if(MAX_HEADER_BYTES == vmi_read_pa(vmi, kernel_base_p, pe, MAX_HEADER_BYTES)) {

        struct pe_header *pe_header = NULL;
        uint16_t optional_header_type = 0;
        struct optional_header_pe32 *oh32 = NULL;
        struct optional_header_pe32plus *oh32plus = NULL;

        peparse_assign_headers(pe, NULL, &pe_header, &optional_header_type, NULL, &oh32, &oh32plus);

        if(optional_header_type == IMAGE_PE32_PLUS_MAGIC) {
            // 64-bit
            vmi->page_mode = VMI_PM_IA32E;
            goto found_pm;
        }

        // 32-bit, determine if PAE/non-PAE
        addr_t debug_offset = peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_DEBUG, NULL, NULL, oh32, oh32plus);

        struct image_debug_directory debug_directory;
        vmi_read_pa(vmi, kernel_base_p + debug_offset, (uint8_t *)&debug_directory, sizeof(struct image_debug_directory));

        struct cv_info_pdb70 *pdb_header = malloc(debug_directory.size_of_data);
        vmi_read_pa(vmi, kernel_base_p + debug_directory.address_of_raw_data, pdb_header, debug_directory.size_of_data);

        // The PDB header has to be PDB 7.0
        // http://www.debuginfo.com/articles/debuginfomatch.html
        if(pdb_header->cv_signature == RSDS) {
            dbprint("The CodeView debug information has to be in PDB 7.0 for the kernel!\n");
            goto error_exit;
        }

        dbprint("**kernel filename: %s\n", pdb_header->pdb_file_name);

        //NTOSKRNL, single-processor without PAE
        //NTKRNLMP, multi-processor without PAE
        //NTKRNLPA, single-processor with PAE (version 5.0 and higher)
        //NTKRPAMP, multi-processor with PAE (version 5.0 and higher)

        if(!strcmp("ntoskrnl.pdb", pdb_header->pdb_file_name)) {
            vmi->page_mode = VMI_PM_LEGACY;
            goto found_pm;
        } else
        if(!strcmp("ntkrnlmp.pdb", pdb_header->pdb_file_name)) {
            vmi->page_mode = VMI_PM_LEGACY;
            goto found_pm;
        } else
        if(!strcmp("ntkrnlpa.pdb", pdb_header->pdb_file_name)) {
            vmi->page_mode = VMI_PM_PAE;
            goto found_pm;
        } else
        if(!strcmp("ntkrpamp.pdb", pdb_header->pdb_file_name)) {
            vmi->page_mode = VMI_PM_PAE;
            goto found_pm;
        }
    }

error_exit:
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
    addr_t sysproc = vmi->os.windows_instance.sysproc;

    /* get address for System process */
    if (!sysproc) {
        if ((sysproc = windows_find_eprocess(vmi, "System")) == 0) {
            dbprint("--failed to find System process.\n");
            goto error_exit;
        }
        printf
            ("LibVMI Suggestion: set win_sysproc=0x%llx in libvmi.conf for faster startup.\n",
             sysproc);
    }
    dbprint("--got PA to PsInititalSystemProcess (0x%.16llx).\n",
            sysproc);

    /* get address for page directory (from system process) */
    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                         sysproc +
                         vmi->os.windows_instance.pdbase_offset,
                         &vmi->kpgd)) {
        dbprint("--failed to resolve PD for Idle process\n");
        goto error_exit;
    }

    if (!vmi->kpgd) {
        dbprint("--kpgd was zero\n");
        goto error_exit;
    }
    dbprint("**set kpgd (0x%.16llx).\n", vmi->kpgd);

    vmi_read_addr_pa(vmi,
                     sysproc + vmi->os.windows_instance.tasks_offset,
                     &vmi->init_task);
    dbprint("**set init_task (0x%.16llx).\n", vmi->init_task);

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

    if (VMI_FAILURE ==
        vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &sysproc)) {
        dbprint("--failed to read pointer for system process\n");
        goto error_exit;
    }
    sysproc = vmi_translate_kv2p(vmi, sysproc);
    dbprint("--got PA to PsInititalSystemProcess (0x%.16llx).\n",
            sysproc);

    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                         sysproc +
                         vmi->os.windows_instance.pdbase_offset,
                         &vmi->kpgd)) {
        dbprint("--failed to resolve pointer for system process\n");
        goto error_exit;
    }

    if (!vmi->kpgd) {
        dbprint("--kpgd was zero\n");
        goto error_exit;
    }
    dbprint("**set kpgd (0x%.16llx).\n", vmi->kpgd);

    vmi_read_addr_pa(vmi,
                     sysproc + vmi->os.windows_instance.tasks_offset,
                     &vmi->init_task);
    dbprint("**set init_task (0x%.16llx).\n", vmi->init_task);

    return VMI_SUCCESS;
error_exit:
    return VMI_FAILURE;
}

static status_t
get_kpgd_method0(
    vmi_instance_t vmi)
{
    addr_t sysproc = 0;

    if (VMI_FAILURE ==
        windows_symbol_to_address(vmi, "PsActiveProcessHead",
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
        vmi->os.windows_instance.tasks_offset;
    dbprint("--got PA to PsActiveProcessHead (0x%.16llx).\n", sysproc);

    if (VMI_FAILURE ==
        vmi_read_addr_pa(vmi,
                         sysproc +
                         vmi->os.windows_instance.pdbase_offset,
                         &vmi->kpgd)) {
        dbprint("--failed to resolve pointer for system process\n");
        goto error_exit;
    }

    if (!vmi->kpgd) {
        dbprint("--kpgd was zero\n");
        goto error_exit;
    }
    dbprint("**set kpgd (0x%.16llx).\n", vmi->kpgd);

    vmi_read_addr_pa(vmi,
                     sysproc + vmi->os.windows_instance.tasks_offset,
                     &vmi->init_task);
    dbprint("**set init_task (0x%.16llx).\n", vmi->init_task);
    return VMI_SUCCESS;
error_exit:
    return VMI_FAILURE;
}

status_t
windows_init(
    vmi_instance_t vmi)
{

    /* determine page mode */
    if (VMI_PM_UNKNOWN == vmi->page_mode) {
        if (VMI_SUCCESS == find_page_mode(vmi))
            goto found_pm;
        else
        if (VMI_SUCCESS == find_page_mode2(vmi))
            goto found_pm;
        else {
            errprint("Failed to determine page mode!\n");
            goto error_exit;
        }
    }

found_pm:
    /* get base address for kernel image in memory */
    if (VMI_FAILURE ==
        windows_symbol_to_address(vmi, "KernBase",
                                  &vmi->os.windows_instance.
                                  ntoskrnl_va)) {
        errprint("Address translation failure.\n");
        goto error_exit;
    }

    dbprint("**ntoskrnl @ VA 0x%.16llx.\n",
            vmi->os.windows_instance.ntoskrnl_va);

    vmi->os.windows_instance.ntoskrnl =
        vmi_translate_kv2p(vmi, vmi->os.windows_instance.ntoskrnl_va);
    dbprint("**set ntoskrnl (0x%.16llx).\n",
            vmi->os.windows_instance.ntoskrnl);


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
    return VMI_FAILURE;
}

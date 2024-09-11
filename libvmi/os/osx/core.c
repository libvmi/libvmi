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
#include "os/osx/osx.h"
#include "os/osx/xnu.h"
#include <string.h>


static status_t init_kernel_load_address(vmi_instance_t vmi);

static status_t init_kern_mmap(vmi_instance_t
                               vmi);

void osx_read_config_ghashtable_entries(char *key, gpointer value,
                                        vmi_instance_t vmi);

static status_t init_from_json_profile(vmi_instance_t vmi)
{

    status_t ret = VMI_FAILURE;
    osx_instance_t osx_instance = vmi->os_data;
    osx_offsets_t *offsets = &osx_instance->offsets;


    if (!offsets->p_pid) {
        CHECK_SUCCESS(json_profile_lookup(vmi, "proc", "p_pid", &offsets->p_pid));
    }
    if (!offsets->p_comm) {
        CHECK_SUCCESS(json_profile_lookup(vmi, "proc", "p_comm", &offsets->p_comm));
    }
    if (!offsets->vmspace) {
        CHECK_SUCCESS(json_profile_lookup(vmi, "task", "map", &offsets->vmspace));
    }
    if (!offsets->pgd) {
        CHECK_SUCCESS(json_profile_lookup(vmi, "pmap", "pm_cr3", &offsets->pgd));
    }
    if (!offsets->pm_ucr3) {
        CHECK_SUCCESS(json_profile_lookup(vmi, "pmap", "pm_ucr3", &offsets->pgd));
    }
    if (!offsets->pmap) {
        CHECK_SUCCESS(json_profile_lookup(vmi, "_vm_map", "pmap", &offsets->pmap));
    }
    if (!osx_instance->_mh_execute_header) {
        CHECK_SUCCESS(json_profile_lookup(vmi, "_mh_execute_header", NULL, &osx_instance->_mh_execute_header));
    }
    if (!osx_instance->proc_size) {
        CHECK_SUCCESS(vmi->json.handler(vmi->json.root, "proc", NULL, NULL, &osx_instance->proc_size));
    }

    ret = VMI_SUCCESS;
done:
    return ret;
}

status_t osx_init(vmi_instance_t vmi, GHashTable *config)
{

    status_t status = VMI_FAILURE;
    os_interface_t os_interface = NULL;

    CHECK((config != NULL));

    if (vmi->os_data != NULL) {
        errprint("os data already initialized, reinitializing\n");
        free(vmi->os_data);
    }

    vmi->os_data = g_try_malloc0(sizeof(struct osx_instance));
    if (!vmi->os_data) {
        return VMI_FAILURE;
    }

    g_hash_table_foreach(config, (GHFunc) osx_read_config_ghashtable_entries,
                         vmi);

    CHECK_SUCCESS(init_from_json_profile(vmi));


#if defined(I386) || defined(X86_64)
    CHECK_SUCCESS(driver_get_vcpureg(vmi, &vmi->kpgd, CR3, 0));
#endif

    dbprint(VMI_DEBUG_MISC, "**set vmi->kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    os_interface = g_malloc(sizeof(struct os_interface));
    CHECK(os_interface);

    bzero(os_interface, sizeof(struct os_interface));
    os_interface->os_get_offset = osx_get_offset;
    os_interface->os_pid_to_pgd = osx_pid_to_pgd;
    os_interface->os_pgd_to_pid = osx_pgd_to_pid;
    os_interface->os_ksym2v = osx_symbol_to_address;
    os_interface->os_usym2rva = NULL;
    os_interface->os_v2sym = NULL;
    os_interface->os_read_unicode_struct = NULL;
    os_interface->os_teardown = osx_teardown;

    vmi->os_interface = os_interface;

    CHECK_SUCCESS(vmi_pause_vm(vmi));
    CHECK_SUCCESS(init_kernel_load_address(vmi));
    CHECK_SUCCESS(init_kern_mmap(vmi));
    CHECK_SUCCESS(osx_symbol_to_address(vmi, "allproc", NULL, &vmi->init_task));

    vmi_resume_vm(vmi);
    return VMI_SUCCESS;

done:
    osx_teardown(vmi);
    return status;
}

status_t osx_get_offset(vmi_instance_t vmi, const char *offset_name, addr_t *offset)
{
    const size_t max_length = 100;
    osx_instance_t osx_instance = vmi->os_data;
    osx_offsets_t *offsets = &osx_instance->offsets;

    CHECK((osx_instance != NULL));
    CHECK((offset_name != NULL || offset != NULL));

    if (strncmp(offset_name, "osx_pmap", max_length) == 0) {
        *offset = offsets->pmap;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "osx_vmspace", max_length) == 0) {
        *offset = offsets->vmspace;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "osx_pid", max_length) == 0) {
        *offset = offsets->p_pid;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "osx_name", max_length) == 0) {
        *offset = offsets->p_comm;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "kslide", max_length) == 0) {
        *offset = osx_instance->k_mmap.slide;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "kernel_load_address", max_length) == 0) {
        *offset = osx_instance->k_mmap.load_address;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "osx_pgd", max_length) == 0) {
        *offset = offsets->pgd;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "kpgd", max_length) == 0) {
        *offset = vmi->kpgd;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "osx_procsize", max_length) == 0) {
        *offset = osx_instance->proc_size;
        return VMI_SUCCESS;
    }

    warnprint("Invalid offset name in osx_get_offset (%s).\n", offset_name);
done:
    return VMI_FAILURE;
}


void osx_read_config_ghashtable_entries(char *key, gpointer value,
                                        vmi_instance_t vmi)
{

    osx_instance_t osx_instance = vmi->os_data;
    osx_offsets_t *offsets = &osx_instance->offsets;

    CHECK((key != NULL || value != NULL));

    if (strncmp(key, "osx_pmap", CONFIG_STR_LENGTH - 1) == 0) {
        offsets->pmap = *(addr_t *) value;
        goto done;
    }

    if (strncmp(key, "osx_vmspace", CONFIG_STR_LENGTH - 1) == 0) {
        offsets->vmspace = *(addr_t *) value;
        goto done;
    }

    if (strncmp(key, "osx_pid", CONFIG_STR_LENGTH - 1) == 0) {
        offsets->p_pid = *(addr_t *) value;
        goto done;
    }

    if (strncmp(key, "osx_name", CONFIG_STR_LENGTH - 1) == 0) {
        offsets->p_comm = *(addr_t *) value;
        goto done;
    }

    if (strncmp(key, "osx_pgd", CONFIG_STR_LENGTH - 1) == 0) {
        offsets->pgd = *(addr_t *) value;
        goto done;
    }

    if (strncmp(key, "kpgd", CONFIG_STR_LENGTH - 1) == 0) {
        vmi->kpgd = *(addr_t *) value;
        goto done;
    }
done:
    return;
}


status_t osx_teardown(vmi_instance_t vmi)
{

    osx_instance_t osx_instance = vmi->os_data;
    osx_mapping_t k_mmap = osx_instance->k_mmap;
    if (osx_instance == NULL) {
        goto done;
    }
    if (k_mmap.segments == NULL) {
        goto done;
    }

    free(k_mmap.segments);
    k_mmap.segments = NULL;

    free(vmi->os_data);
    vmi->os_data = NULL;
done:
    return VMI_SUCCESS;
}


static status_t init_kernel_load_address(vmi_instance_t vmi)
{
    /*
     In order to find the real loading address of the kernel, we need to do the following:
       - Retrieve _mh_execute_header address from json profile - This is the unslide kernel address.
       - Iterate over the kernel address space and look for mach magic 0xfeedfacf.
       - The kernel is load with MH_PIE flag. so, when we have a match it is the slided load address.
       - set kernel load address and calculate kernel slide.
     */
    osx_instance_t osx_instance = vmi->os_data;

    addr_t current;
    addr_t kernel_text_start = osx_instance->_mh_execute_header;
    addr_t kernel_text_end = kernel_text_start + (1024 * 1024 * 1024);
    osx_mapping_t *k_mmap = &osx_instance->k_mmap;
    kernel_mach_header_t mh = {0};
    status_t status = VMI_FAILURE;

    for (current = kernel_text_start; current < kernel_text_end; current += PAGE_SIZE) {
        // https://github.com/apple-oss-distributions/xnu/blob/aca3beaa3dfbd42498b42c5e5ce20a938e6554e5/osfmk/i386/i386_vm_init.c#L299
        vmi_read_va(vmi, current, 0, sizeof(kernel_mach_header_t), &mh, NULL);
        if (mh.magic != MH_MAGIC_64) {
            continue;
        }
        if (!(mh.flags & MH_PIE)) {
            continue;
        }
        k_mmap->load_address = current;
        k_mmap->slide = current - kernel_text_start;

        dbprint(VMI_DEBUG_OSX, "** Calculated Kernel load address 0x%"PRIx64" |  Kernel slide 0x%x\n",
                k_mmap->load_address,
                k_mmap->slide);
        status = VMI_SUCCESS;
        break;
    }
    return status;

}

static status_t init_kern_mmap(vmi_instance_t vmi)
{
    /*
     This step is required inorder to correctly translate symbols to addresses.
     In addition to kernel aslr it appears that segments relocation is done during loading.

     This function will parse the load commands and retrieve the memory map of the loaded segments with their corresponding file addresses.
     E.g:
     __DATA_CONST will be after __DATA on the file, however on memory will be relocate above __TEXT

        Name                             File                                   Memory                    Size
        __TEXT          [0xffffff8000200000-0xffffff8000c00000)	[0xffffff8014adc000-0xffffff80154dc000)	[0xa00000]
        __DATA          [0xffffff8000c00000-0xffffff8000e90000)	[0xffffff8015890000-0xffffff8015b20000)	[0x290000]
        __DATA_CONST    [0xffffff8000e90000-0xffffff8000f5b000)	[0xffffff8014a10000-0xffffff8014adb000)	[0xcb000]
        __KLDDATA       [0xffffff8000f5b000-0xffffff8000f97000)	[0xffffff8015b20000-0xffffff8015b5c000)	[0x3c000]
        __HIB           [0xffffff8000f97000-0xffffff8001036000)	[0xffffff8014900000-0xffffff801499f000)	[0x9f000]
        __VECTORS       [0xffffff8001036000-0xffffff8001037000)	[0xffffff8015b5c000-0xffffff8015b5d000)	[0x1000]
        __KLD           [0xffffff8001037000-0xffffff8001049000)	[0xffffff80154dc000-0xffffff80154ee000)	[0x12000]
        __LASTDATA_CONS [0xffffff8001049000-0xffffff800104a000)	[0xffffff8014adb000-0xffffff8014adc000)	[0x1000]
        __LAST          [0xffffff800104a000-0xffffff800104a000)	[0xffffff8015b5d000-0xffffff8015b5d000)	[0x0]
        __PRELINK_TEXT  [0xffffff800104a000-0xffffff800104a000)	[0xffffff80154ee000-0xffffff80154ee000)	[0x0]
        __PRELINK_INFO  [0xffffff800104a000-0xffffff80013b0000)	[0xffffff8019089000-0xffffff80193ef000)	[0x366000]
        __LINKINFO      [0xffffff80013b0000-0xffffff80013f9000)	[0xffffff8017f9c000-0xffffff8017fe5000)	[0x49000]
        __CTF           [0xffffff80013f9000-0xffffff80013f9000)	[0xffffff8014a10000-0xffffff8014a10000)	[0x0]
        __LINKEDIT      [0xffffff80013f9000-0xffffff8001eab064)	[0xffffff801802c000-0xffffff8018ade064)	[0xab2064]
     */
    osx_instance_t osx_instance = vmi->os_data;
    kernel_mach_header_t mh = {0};
    status_t status = VMI_FAILURE;
    kernel_segment_command_t sgp;
    addr_t current, seg_fstart;
    uint32_t j = 0;
    osx_segment_t *k_seg;

    osx_mapping_t *k_mmap = &osx_instance->k_mmap;
    CHECK_SUCCESS(vmi_read_va(vmi, k_mmap->load_address, 0, sizeof(kernel_mach_header_t), &mh, NULL));

    current = k_mmap->load_address + sizeof(kernel_mach_header_t);
    CHECK_SUCCESS(vmi_read_va(vmi, current, 0, sizeof(kernel_segment_command_t), &sgp, NULL));
    /*
    (lldb) p (kernel_segment_command_t *)(&_mh_execute_header+32)
    (kernel_segment_command_t *) $15 = 0xffffff801e2dc100
    (lldb) p $15->
    Available completions:
    $15->operator=(            -- inline segment_command_64 &operator=(const segment_command_64 &)
    $15->~segment_command_64() -- inline ~segment_command_64()
    $15->flags                 -- uint32_t
    $15->nsects                -- uint32_t
    $15->vmaddr                -- uint64_t
    $15->vmsize                -- uint64_t
    $15->cmdsize               -- uint32_t
    $15->fileoff               -- uint64_t
    $15->maxprot               -- vm_prot_t
    $15->segname               -- char[16]
    $15->filesize              -- uint64_t
    $15->initprot              -- vm_prot_t
    $15->cmd                   -- uint32_t
    */
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        if (sgp.cmd == LC_SEGMENT_KERNEL) {
            k_mmap->count++;
        }
        current += sgp.cmdsize;
        CHECK_SUCCESS(vmi_read_va(vmi, current, 0, sizeof(kernel_segment_command_t), &sgp, NULL));
    }
    k_mmap->segments = (osx_segment_t *) malloc(k_mmap->count * sizeof(osx_segment_t));
    CHECK((k_mmap->segments != NULL));

    seg_fstart = osx_instance->_mh_execute_header;

    current = k_mmap->load_address + sizeof(kernel_mach_header_t);
    CHECK_SUCCESS(vmi_read_va(vmi, current, 0, sizeof(kernel_segment_command_t), &sgp, NULL));
    dbprint(VMI_DEBUG_OSX, "%5s %32s %40s %23s\n", "Name", "File", "Memory", "Size");
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        current += sgp.cmdsize;
        if (sgp.cmd != LC_SEGMENT_KERNEL) {
            continue;
        }
        k_seg = &k_mmap->segments[j++];
        k_seg->mstart = sgp.vmaddr;
        k_seg->mend = sgp.vmaddr + sgp.vmsize;
        k_seg->size = sgp.vmsize;
        k_seg->fstart = seg_fstart;
        k_seg->fend = k_seg->fstart + sgp.vmsize;
        seg_fstart = k_seg->fend;
        g_strlcpy(k_seg->name, sgp.segname, 16);
        dbprint(VMI_DEBUG_OSX, "%-15s [0x%2"PRIx64"-0x%2"PRIx64")\t[0x%2"PRIx64"-0x%2"PRIx64")\t[0x%lx]\n", k_seg->name,
                k_seg->fstart, k_seg->fend, k_seg->mstart, k_seg->mend, k_seg->size);
        CHECK_SUCCESS(vmi_read_va(vmi, current, 0, sizeof(kernel_segment_command_t), &sgp, NULL));
    }
    status = VMI_SUCCESS;
done:
    return status;
}
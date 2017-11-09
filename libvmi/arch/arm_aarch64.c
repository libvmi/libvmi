/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel (tamas@tklengyel.com)
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

#include <glib.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "private.h"
#include "driver/driver_wrapper.h"
#include "arch/arm_aarch64.h"

// 0th Level Page Table Index (4kb Pages)
static inline
uint64_t zero_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 39) & VMI_BIT_MASK(0,8);
}

// 0th Level Descriptor (4kb Pages)
static inline
void get_zero_level_4kb_descriptor(vmi_instance_t vmi, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.zld_location = (dtb & VMI_BIT_MASK(12,47)) | (zero_level_4kb_table_index(vaddr) << 3);
    uint64_t zld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.zld_location, &zld_v)) {
        printf("Got zld_v: 0x%lx\n", zld_v);
        info->arm_aarch64.zld_value = zld_v;
    }
}

// 1st Level Page Table Index (4kb Pages)
static inline
uint64_t first_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 30) & VMI_BIT_MASK(0,8);
}

// 1st Level Descriptor (4kb Pages)
static inline
void get_first_level_4kb_descriptor(vmi_instance_t vmi, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.fld_location = (dtb & VMI_BIT_MASK(12,47)) | (first_level_4kb_table_index(vaddr) << 3);
    uint64_t fld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.fld_location, &fld_v)) {
        info->arm_aarch64.fld_value = fld_v;
    }
}

// 1st Level Page Table Index (64kb Pages)
static inline
uint64_t first_level_64kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 42) & VMI_BIT_MASK(0,5);
}

// 1st Level Descriptor (64kb Pages)
static inline
void get_first_level_64kb_descriptor(vmi_instance_t vmi, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.fld_location = (dtb & VMI_BIT_MASK(9,47)) | (first_level_64kb_table_index(vaddr) << 3);
    uint64_t fld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.fld_location, &fld_v)) {
        info->arm_aarch64.fld_value = fld_v;
    }

    printf("64kb fld location: 0x%lx 0x%lx\n", info->arm_aarch64.fld_location, fld_v);
}

// 2nd Level Page Table Index (4kb Pages)
static inline
uint64_t second_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr>>21) & VMI_BIT_MASK(0,8);
}

// 2nd Level Page Table Descriptor (4kb Pages)
static inline
void get_second_level_4kb_descriptor(vmi_instance_t vmi, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.sld_location = (dtb & VMI_BIT_MASK(12,47)) | (second_level_4kb_table_index(vaddr) << 3);
    uint64_t sld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.sld_location, &sld_v)) {
        info->arm_aarch64.sld_value = sld_v;
    }
}

// 2nd Level Page Table Index (64kb Pages)
static inline
uint64_t second_level_64kb_table_index(uint64_t vaddr)
{
    return (vaddr>>29) & VMI_BIT_MASK(0,12);
}

// 2nd Level Page Table Descriptor (64kb Pages)
static inline
void get_second_level_64kb_descriptor(vmi_instance_t vmi, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.sld_location = (dtb & VMI_BIT_MASK(16,47)) | (second_level_64kb_table_index(vaddr) << 3);
    uint64_t sld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.sld_location, &sld_v)) {
        info->arm_aarch64.sld_value = sld_v;
    }
}

// 3rd Level Page Table Index (4kb Pages)
static inline
uint64_t third_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr>>12) & VMI_BIT_MASK(0,8);
}

// 3rd Level Page Table Descriptor (4kb Pages)
static inline
void get_third_level_4kb_descriptor(vmi_instance_t vmi, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.tld_location = (info->arm_aarch64.sld_value & VMI_BIT_MASK(12,47)) | (third_level_4kb_table_index(vaddr) << 3);
    uint64_t tld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.tld_location, &tld_v)) {
        info->arm_aarch64.tld_value = tld_v;
    }
}

// 3rd Level Page Table Index (64kb Pages)
static inline
uint64_t third_level_64kb_table_index(uint64_t vaddr)
{
    return (vaddr>>16) & VMI_BIT_MASK(0,12);
}

// 3rd Level Page Table Descriptor (64kb Pages)
static inline
void get_third_level_64kb_descriptor(vmi_instance_t vmi, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.tld_location = (info->arm_aarch64.sld_value & VMI_BIT_MASK(16,47)) | (third_level_64kb_table_index(vaddr) << 3);
    uint64_t tld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.tld_location, &tld_v)) {
        info->arm_aarch64.tld_value = tld_v;
    }
}

// Based on ARM Reference Manual
// D4.3 ARM ARMv8-A VMSAv8-64 translation table format descriptors
// K7.1.2 ARM ARMv8-A Full translation flows for VMSAv8-64 address translation
status_t v2p_aarch64 (vmi_instance_t vmi,
                      addr_t dtb,
                      addr_t vaddr,
                      page_info_t *info)
{
    status_t status = VMI_FAILURE;

    dbprint(VMI_DEBUG_PTLOOKUP, "--ARM AArch64 PTLookup: vaddr = 0x%.16"PRIx64", dtb = 0x%.16"PRIx64"\n", vaddr, dtb);

    /*
     * TODO: Fixme
     * We need to know if we are using TTBR0 or TTBR1 here so we know table type.
     * Right now we can deduce this for Linux by comparing to vmi->kpgd which is
     * TTBR1. However, this means V2P translation only works with complete init.
     * To make this OS neutral we will likely have to extend the API so the user
     * can specify the dtb type.
     */

    bool is_dtb_ttbr1 = false;
    page_size_t ps;
    uint8_t levels;
    uint8_t va_width;

    if (dtb == vmi->kpgd)
        is_dtb_ttbr1 = true;

    if ( is_dtb_ttbr1 ) {
        ps = vmi->arm64.tg1;
        va_width = 64 - vmi->arm64.t1sz;
    } else {
        ps = vmi->arm64.tg0;
        va_width = 64 - vmi->arm64.t0sz;
    }

    if ( VMI_PS_4KB == ps )
        levels = va_width == 39 ? 3 : 4;
    else if ( VMI_PS_64KB == ps )
        levels = va_width == 42 ? 2 : 3;
    else {
        errprint("16KB granule size ARM64 lookups are not yet implemented\n");
        goto done;
    }

    if ( 4 == levels ) {
        /* Only true when ps == VMI_PS_4KB */
        get_zero_level_4kb_descriptor(vmi, dtb, vaddr, info);
        dbprint(VMI_DEBUG_PTLOOKUP,
                "--ARM AArch64 PTLookup: zld_value = 0x%"PRIx64"\n",
                info->arm_aarch64.zld_value);

        if ( (info->arm_aarch64.zld_value & VMI_BIT_MASK(0,1)) != 0b11)
            goto done;

        dtb = info->arm_aarch64.zld_value & VMI_BIT_MASK(12,47);
        --levels;
    }

    if ( 3 == levels) {
        if ( VMI_PS_4KB == ps ) {
            get_first_level_4kb_descriptor(vmi, dtb, vaddr, info);
            dbprint(VMI_DEBUG_PTLOOKUP,
                    "--ARM AArch64 4kb PTLookup: fld_value = 0x%"PRIx64"\n",
                    info->arm_aarch64.fld_value);

            switch (info->arm_aarch64.fld_value & VMI_BIT_MASK(0,1)) {
                case 0b11:
                    dtb = info->arm_aarch64.fld_value & VMI_BIT_MASK(12,47);
                    --levels;
                    break;
                case 0b01:
                    info->size = VMI_PS_1GB;
                    info->paddr = (info->arm_aarch64.fld_value & VMI_BIT_MASK(30,47)) | (vaddr & VMI_BIT_MASK(0,29));
                    status = VMI_SUCCESS;
                    goto done;
                default:
                    goto done;
            }

        }
        if ( VMI_PS_64KB == ps ) {
            get_first_level_64kb_descriptor(vmi, dtb, vaddr, info);
            dbprint(VMI_DEBUG_PTLOOKUP,
                    "--ARM AArch64 64kb PTLookup: fld_value = 0x%"PRIx64"\n",
                    info->arm_aarch64.fld_value);

            switch (info->arm_aarch64.fld_value & VMI_BIT_MASK(0,1)) {
                case 0b11:
                    dtb = info->arm_aarch64.fld_value & VMI_BIT_MASK(16,47);
                    --levels;
                    break;
                default:
                    goto done;
            }
        }
    }

    if ( 2 == levels ) {
        if ( VMI_PS_4KB == ps ) {
            get_second_level_4kb_descriptor(vmi, dtb, vaddr, info);
            dbprint(VMI_DEBUG_PTLOOKUP,
                    "--ARM AArch64 4kb PTLookup: sld_value = 0x%"PRIx64"\n",
                    info->arm_aarch64.sld_value);

            switch (info->arm_aarch64.sld_value & VMI_BIT_MASK(0,1)) {
                case 0b11:
                    get_third_level_4kb_descriptor(vmi, vaddr, info);
                    dbprint(VMI_DEBUG_PTLOOKUP,
                            "--ARM AArch64 4kb PTLookup: tld_value = 0x%"PRIx64"\n",
                            info->arm_aarch64.tld_value);

                    info->size = VMI_PS_4KB;
                    info->paddr = (info->arm_aarch64.tld_value & VMI_BIT_MASK(12,47)) | (vaddr & VMI_BIT_MASK(0,11));
                    status = VMI_SUCCESS;
                    break;
                case 0b01:
                    info->size = VMI_PS_2MB;
                    info->paddr = (info->arm_aarch64.sld_value & VMI_BIT_MASK(21,47)) | (vaddr & VMI_BIT_MASK(0,20));
                    status = VMI_SUCCESS;
                    goto done;
                default:
                    goto done;
            }
        }
        if ( VMI_PS_64KB == ps ) {
            get_second_level_64kb_descriptor(vmi, dtb, vaddr, info);
            dbprint(VMI_DEBUG_PTLOOKUP,
                    "--ARM AArch64 64kb PTLookup: sld_value = 0x%"PRIx64"\n",
                    info->arm_aarch64.sld_value);

            switch (info->arm_aarch64.sld_value & VMI_BIT_MASK(0,1)) {
                case 0b11:
                    get_third_level_64kb_descriptor(vmi, vaddr, info);
                    dbprint(VMI_DEBUG_PTLOOKUP,
                            "--ARM AArch64 64kb PTLookup: tld_value = 0x%"PRIx64"\n",
                            info->arm_aarch64.tld_value);

                    info->size = VMI_PS_4KB;
                    info->paddr = (info->arm_aarch64.tld_value & VMI_BIT_MASK(16,47)) | (vaddr & VMI_BIT_MASK(0,15));
                    status = VMI_SUCCESS;
                    goto done;
                case 0b01:
                    info->size = VMI_PS_512MB;
                    info->paddr = (info->arm_aarch64.sld_value & VMI_BIT_MASK(29,47)) | (vaddr & VMI_BIT_MASK(0,28));
                    status = VMI_SUCCESS;
                    goto done;
                default:
                    goto done;
            }
        }
    }

done:
    dbprint(VMI_DEBUG_PTLOOKUP, "--ARM PTLookup: PA = 0x%"PRIx64"\n", info->paddr);
    return status;
}

GSList* get_va_pages_aarch64(vmi_instance_t UNUSED(vmi), addr_t UNUSED(dtb))
{
    //TODO: investigate best method to loop over all tables
    return NULL;
}

status_t aarch64_init(vmi_instance_t vmi)
{

    if (!vmi->arch_interface) {
        vmi->arch_interface = g_malloc0(sizeof(struct arch_interface));
        if ( !vmi->arch_interface )
            return VMI_FAILURE;
    }

    vmi->arch_interface->v2p = v2p_aarch64;
    vmi->arch_interface->get_va_pages = get_va_pages_aarch64;

    return VMI_SUCCESS;
}

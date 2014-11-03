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
#include "driver/driver_wrapper.h"
#include "x86.h"
#include "amd64.h"
#include <glib.h>
#include <stdlib.h>
#include <sys/mman.h>

/* PML4 Table  */
static inline
addr_t get_pml4_index (addr_t vaddr)
{
    return (vaddr & VMI_BIT_MASK(39,47)) >> 36;
}

static inline
uint64_t get_pml4e (vmi_instance_t vmi,
    addr_t vaddr,
    reg_t cr3,
    addr_t *pml4e_address)
{
    uint64_t value;
    *pml4e_address = (cr3 & VMI_BIT_MASK(12,51)) | get_pml4_index(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pml4e_address = 0x%.16"PRIx64"\n", *pml4e_address);
    if(VMI_FAILURE == vmi_read_64_pa(vmi, *pml4e_address, &value)) {
        value = 0;
    }
    return value;
}

static inline
addr_t get_pdpt_index_ia32e (addr_t vaddr)
{
    return (vaddr & VMI_BIT_MASK(30,38)) >> 27;
}

static inline
uint64_t get_pdpte_ia32e (vmi_instance_t vmi,
    addr_t vaddr,
    uint64_t pml4e,
    addr_t *pdpte_address)
{
    uint64_t value;
    *pdpte_address = (pml4e & VMI_BIT_MASK(12,51)) | get_pdpt_index_ia32e(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpte_address = 0x%.16"PRIx64"\n", *pdpte_address);
    if(VMI_FAILURE == vmi_read_64_pa(vmi, *pdpte_address, &value)) {
        value = 0;
    }
    return value;
}

static inline
uint64_t get_pd_index_ia32e (addr_t vaddr)
{
    return (vaddr & VMI_BIT_MASK(21,29)) >> 18;
}

static inline
uint64_t get_pde_ia32e (vmi_instance_t vmi,
    addr_t vaddr,
    uint64_t pdpte,
    addr_t *pde_address)
{
    uint64_t value;
    *pde_address = (pdpte & VMI_BIT_MASK(12,51)) | get_pd_index_ia32e(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pde_address = 0x%.16"PRIx64"\n", *pde_address);
    if(VMI_FAILURE == vmi_read_64_pa(vmi, *pde_address, &value)) {
        value = 0;
    }
    return value;
}

static inline
uint64_t get_pt_index_ia32e (addr_t vaddr)
{
    return (vaddr & VMI_BIT_MASK(12,20)) >> 9;
}

static inline
uint64_t get_pte_ia32e (vmi_instance_t vmi,
    addr_t vaddr,
    uint64_t pde,
    addr_t *pte_address)
{
    uint64_t value;
    *pte_address = (pde & VMI_BIT_MASK(12,51)) | get_pt_index_ia32e(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_address = 0x%.16"PRIx64"\n", *pte_address);
    if(VMI_FAILURE == vmi_read_64_pa(vmi, *pte_address, &value)) {
        value = 0;
    }
    return value;
}

static inline
uint64_t get_paddr_ia32e (addr_t vaddr, uint64_t pte)
{
    return (pte & VMI_BIT_MASK(12,51)) | (vaddr & VMI_BIT_MASK(0,11));
}

static inline
uint64_t get_gigpage_ia32e (addr_t vaddr, uint64_t pdpte)
{
    return (pdpte & VMI_BIT_MASK(30,51)) | (vaddr & VMI_BIT_MASK(0,29));
}

static inline
uint64_t get_2megpage_ia32e (addr_t vaddr, uint64_t pde)
{
    return (pde & VMI_BIT_MASK(21,51)) | (vaddr & VMI_BIT_MASK(0,20));
}

addr_t v2p_ia32e (vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    page_info_t *info)
{

    // are we in compatibility mode OR 64-bit mode ???

    // validate address based on above (e.g., is it canonical?)

    // determine what MAXPHYADDR is

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: lookup vaddr = 0x%.16"PRIx64"\n", vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: dtb = 0x%.16"PRIx64"\n", dtb);
    info->x86_ia32e.pml4e_value = get_pml4e(vmi, vaddr, dtb, &info->x86_ia32e.pml4e_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pml4e = 0x%.16"PRIx64"\n", info->x86_ia32e.pml4e_value);

    if (!ENTRY_PRESENT(vmi->os_type, info->x86_ia32e.pml4e_value)) {
        goto done;
    }

    info->x86_ia32e.pdpte_value = get_pdpte_ia32e(vmi, vaddr, info->x86_ia32e.pml4e_value, &info->x86_ia32e.pdpte_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpte = 0x%.16"PRIx64"\n", info->x86_ia32e.pdpte_value);

    if (!ENTRY_PRESENT(vmi->os_type, info->x86_ia32e.pdpte_value)) {
        goto done;
    }

    if (PAGE_SIZE(info->x86_ia32e.pdpte_value)) { // pdpte maps a 1GB page
        info->size = VMI_PS_1GB;
        info->paddr = get_gigpage_ia32e(vaddr, info->x86_ia32e.pdpte_value);
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 1GB page\n");
        goto done;
    }

    info->x86_ia32e.pgd_value = get_pde_ia32e(vmi, vaddr, info->x86_ia32e.pdpte_value, &info->x86_ia32e.pgd_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pde = 0x%.16"PRIx64"\n", info->x86_ia32e.pgd_value);

    if (!ENTRY_PRESENT(vmi->os_type, info->x86_ia32e.pgd_value)) {
        goto done;
    }

    if (PAGE_SIZE(info->x86_ia32e.pgd_value)) { // pde maps a 2MB page
        info->size = VMI_PS_2MB;
        info->paddr = get_2megpage_ia32e(vaddr, info->x86_ia32e.pgd_value);
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 2MB page\n");
        goto done;
    }

    info->x86_ia32e.pte_value = get_pte_ia32e(vmi, vaddr, info->x86_ia32e.pgd_value, &info->x86_ia32e.pte_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte = 0x%.16"PRIx64"\n", info->x86_ia32e.pte_value);

    if (!ENTRY_PRESENT(vmi->os_type, info->x86_ia32e.pte_value)) {
        goto done;
    }

    info->size = VMI_PS_4KB;
    info->paddr = get_paddr_ia32e(vaddr, info->x86_ia32e.pte_value);

done:
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: paddr = 0x%.16"PRIx64"\n", info->paddr);
    return info->paddr;
}

GSList* get_va_pages_ia32e(vmi_instance_t vmi, addr_t dtb) {

    GSList *ret = NULL;
    uint8_t entry_size = 0x8;

    #define PDES_AND_PTES_PER_PAGE 0x200 // 0x1000/0x8

    uint64_t pml4e;
    for(pml4e=0;pml4e<PDES_AND_PTES_PER_PAGE;pml4e++) {

        addr_t vaddr = pml4e << 39;
        addr_t pml4e_a = 0;
        uint64_t pml4e_value = get_pml4e(vmi, vaddr, dtb, &pml4e_a);

        if(!ENTRY_PRESENT(vmi->os_type, pml4e_value)) {
            continue;
        }

        uint64_t pdpte;
        for(pdpte=0;pdpte<PDES_AND_PTES_PER_PAGE;pdpte++) {

            vaddr = (pml4e << 39) | (pdpte << 30);

            addr_t pdpte_a = 0;
            uint64_t pdpte_value = get_pdpte_ia32e(vmi, vaddr, pml4e_value, &pdpte_a);
            if(!ENTRY_PRESENT(vmi->os_type, pdpte_value)) {
                continue;
            }

            if(PAGE_SIZE(pdpte_value)) {
                page_info_t *info = g_malloc0(sizeof(page_info_t));
                info->vaddr = vaddr;
                info->paddr = get_gigpage_ia32e(vaddr, pdpte_value);
                info->size = VMI_PS_1GB;
                info->x86_ia32e.pml4e_location = pml4e_a;
                info->x86_ia32e.pml4e_value = pml4e_value;
                info->x86_ia32e.pdpte_location = pdpte_a;
                info->x86_ia32e.pdpte_value = pdpte_value;
                ret = g_slist_prepend(ret, info);
                continue;
            }

            uint64_t pgd_curr = (pdpte_value & VMI_BIT_MASK(12,51));
            uint64_t j;
            for(j=0;j<PTRS_PER_PAE_PGD;j++,pgd_curr+=entry_size) {

                uint64_t soffset = vaddr + (j * PTRS_PER_PAE_PGD * PTRS_PER_PAE_PTE * entry_size);

                uint64_t entry;
                dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pde_address = 0x%.16"PRIx64"\n", pgd_curr);
                if(VMI_FAILURE == vmi_read_64_pa(vmi, pgd_curr, &entry)) {
                    continue;
                }

                if(ENTRY_PRESENT(vmi->os_type, entry)) {

                    if(PAGE_SIZE(entry)) {
                        page_info_t *info = g_malloc0(sizeof(page_info_t));
                        info->vaddr = soffset;
                        info->paddr = get_2megpage_ia32e(vaddr, entry);
                        info->size = VMI_PS_2MB;
                        info->x86_ia32e.pml4e_location = pml4e_a;
                        info->x86_ia32e.pml4e_value = pml4e_value;
                        info->x86_ia32e.pdpte_location = pdpte_a;
                        info->x86_ia32e.pdpte_value = pdpte_value;
                        info->x86_ia32e.pgd_location = pgd_curr;
                        info->x86_ia32e.pgd_value = entry;
                        ret = g_slist_prepend(ret, info);
                        continue;
                    }

                    uint64_t pte_curr = (entry & VMI_BIT_MASK(12,51));
                    uint64_t k;
                    for(k=0;k<PTRS_PER_PAE_PTE;k++,pte_curr+=entry_size) {
                        uint64_t pte_entry;
                        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_address = 0x%.16"PRIx64"\n", pte_curr);
                        if(VMI_FAILURE == vmi_read_64_pa(vmi, pte_curr, &pte_entry)) {
                            continue;
                        }

                        if(ENTRY_PRESENT(vmi->os_type, pte_entry)) {
                            page_info_t *info = g_malloc0(sizeof(page_info_t));
                            info->vaddr = soffset + k * VMI_PS_4KB;
                            info->paddr = get_paddr_ia32e(vaddr, pte_entry);
                            info->size = VMI_PS_4KB;
                            info->x86_ia32e.pml4e_location = pml4e_a;
                            info->x86_ia32e.pml4e_value = pml4e_value;
                            info->x86_ia32e.pdpte_location = pdpte_a;
                            info->x86_ia32e.pdpte_value = pdpte_value;
                            info->x86_ia32e.pgd_location = pgd_curr;
                            info->x86_ia32e.pgd_value = entry;
                            info->x86_ia32e.pte_location = pte_curr;
                            info->x86_ia32e.pte_value = pte_entry;
                            ret = g_slist_prepend(ret, info);
                            continue;
                        }
                    }
                }
            }
        }
    }

    return ret;
}

status_t amd64_init(vmi_instance_t vmi) {

    if(!vmi->arch_interface) {
        vmi->arch_interface = safe_malloc(sizeof(struct arch_interface));
        bzero(vmi->arch_interface, sizeof(struct arch_interface));
    }

    vmi->arch_interface->v2p = v2p_ia32e;
    vmi->arch_interface->get_va_pages = get_va_pages_ia32e;

    return VMI_SUCCESS;
}

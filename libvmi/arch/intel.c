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
#include "x86.h"
#include "intel.h"
#include <glib.h>
#include <stdlib.h>
#include <sys/mman.h>

/* page directory pointer table */
static inline
uint64_t get_pdptb (uint64_t pdpr)
{
    return pdpr & VMI_BIT_MASK(5,63);
}

static inline
uint32_t pdpi_index (uint32_t pdpi)
{
    return (pdpi >> 30) * sizeof(uint64_t);
}

static inline
uint64_t get_pdpi (vmi_instance_t instance,
    uint32_t vaddr,
    addr_t dtb,
    addr_t *pdpi_entry)
{
    uint64_t value;
    *pdpi_entry = get_pdptb(dtb) + pdpi_index(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: pdpi_entry = 0x%.16x\n", *pdpi_entry);
    if(VMI_FAILURE == vmi_read_64_pa(instance, *pdpi_entry, &value)) {
        value = 0;
    }

    return value;
}

/* page directory */
static inline
uint32_t pgd_index_nopae (uint32_t address)
{
    return (((address) >> 22) & VMI_BIT_MASK(0,9)) * sizeof(uint32_t);
}

static inline
uint32_t pgd_index_pae (uint32_t address)
{
    return (((address) >> 21) & VMI_BIT_MASK(0,8)) * sizeof(uint64_t);
}

static inline
uint32_t pdba_base_nopae (uint32_t pdpe)
{
    return pdpe & VMI_BIT_MASK(12,31);
}

static inline
uint64_t pdba_base_pae (uint64_t pdpe)
{
    return pdpe & VMI_BIT_MASK(12,51);
}

static inline
uint32_t get_pgd_nopae (vmi_instance_t instance,
    uint32_t vaddr,
    uint32_t pdpe,
    addr_t *pgd_entry)
{
    uint32_t value;
    *pgd_entry = pdba_base_nopae(pdpe) + pgd_index_nopae(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd_entry = 0x%.8x\n", *pgd_entry);
    if(VMI_FAILURE == vmi_read_32_pa(instance, *pgd_entry, &value)) {
        value = 0;
    }
    return value;
}

static inline
uint64_t get_pgd_pae (vmi_instance_t instance,
    uint32_t vaddr,
    uint64_t pdpe,
    addr_t *pgd_entry)
{
    uint64_t value;
    *pgd_entry = pdba_base_pae(pdpe) + pgd_index_pae(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: pgd_entry = 0x%.8x\n", *pgd_entry);
    if(VMI_FAILURE == vmi_read_64_pa(instance, *pgd_entry, &value)) {
        value = 0;
    }
    return value;
}

/* page table */
static inline
uint32_t pte_index_nopae (uint32_t address)
{
    return (((address) >> 12) & VMI_BIT_MASK(0,9)) * sizeof(uint32_t);
}

static inline
uint32_t pte_index_pae (uint32_t address)
{
    return (((address) >> 12) & VMI_BIT_MASK(0,8)) * sizeof(uint64_t);
}

static inline
uint32_t ptba_base_nopae (uint32_t pde)
{
    return pde & VMI_BIT_MASK(12,31);
}

static inline
uint64_t ptba_base_pae (uint64_t pde)
{
    return pde & VMI_BIT_MASK(12,35);
}

static inline
uint32_t get_pte_nopae (vmi_instance_t instance,
    uint32_t vaddr,
    uint32_t pgd,
    addr_t *pte_entry)
{
    uint32_t value;
    *pte_entry = ptba_base_nopae(pgd) + pte_index_nopae(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_entry = 0x%.8x\n", *pte_entry);
    if(VMI_FAILURE == vmi_read_32_pa(instance, *pte_entry, &value)) {
        value = 0;
    }
    return value;
}

static inline
uint64_t get_pte_pae (vmi_instance_t instance,
    uint32_t vaddr,
    uint64_t pgd,
    addr_t *pte_entry)
{
    uint64_t value;
    *pte_entry = ptba_base_pae(pgd) + pte_index_pae(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: pte_entry = 0x%.8x\n", *pte_entry);
    if(VMI_FAILURE == vmi_read_64_pa(instance, *pte_entry, &value)) {
        value = 0;
    }
    return value;
}

/* page */
static inline
uint32_t pte_pfn_nopae (uint32_t pte)
{
    return pte & VMI_BIT_MASK(12,31);
}

static inline
uint64_t pte_pfn_pae (uint64_t pte)
{
    return pte & VMI_BIT_MASK(12,35);
}

static inline
uint32_t get_paddr_nopae (uint32_t vaddr, uint32_t pte)
{
    return pte_pfn_nopae(pte) | (vaddr & VMI_BIT_MASK(0,11));
}

static inline
uint64_t get_paddr_pae (uint32_t vaddr, uint64_t pte)
{
    return pte_pfn_pae(pte) | (vaddr & VMI_BIT_MASK(0,11));
}

static inline
uint32_t get_large_paddr_nopae (uint32_t vaddr, uint32_t pgd_entry)
{
    return (pgd_entry & VMI_BIT_MASK(22,31)) | (vaddr & VMI_BIT_MASK(0,21));
}

static inline
uint32_t get_large_paddr_pae (uint32_t vaddr, uint32_t pgd_entry)
{
    return (pgd_entry & VMI_BIT_MASK(21,31)) | (vaddr & VMI_BIT_MASK(0,20));
}

void buffalo_nopae (vmi_instance_t instance, uint32_t entry, int pde)
{
    /* similar techniques are surely doable in linux, but for now
     * this is only testing for windows domains */
    if (!instance->os_type == VMI_OS_WINDOWS) {
        return;
    }

    if (!TRANSITION(entry) && !PROTOTYPE(entry)) {
        uint32_t pfnum = (entry >> 1) & VMI_BIT_MASK(0,3);
        uint32_t pfframe = entry & VMI_BIT_MASK(12,31);

        /* pagefile */
        if (pfnum != 0 && pfframe != 0) {
            dbprint(VMI_DEBUG_PTLOOKUP, "--Buffalo: page file = %d, frame = 0x%.8x\n",
                    pfnum, pfframe);
        }
        /* demand zero */
        else if (pfnum == 0 && pfframe == 0) {
            dbprint(VMI_DEBUG_PTLOOKUP, "--Buffalo: demand zero page\n");
        }
    }

    else if (TRANSITION(entry) && !PROTOTYPE(entry)) {
        /* transition */
        dbprint(VMI_DEBUG_PTLOOKUP, "--Buffalo: page in transition\n");
    }

    else if (!pde && PROTOTYPE(entry)) {
        /* prototype */
        dbprint(VMI_DEBUG_PTLOOKUP, "--Buffalo: prototype entry\n");
    }

    else if (entry == 0) {
        /* zero */
        dbprint(VMI_DEBUG_PTLOOKUP, "--Buffalo: entry is zero\n");
    }

    else {
        /* zero */
        dbprint(VMI_DEBUG_PTLOOKUP, "--Buffalo: unknown\n");
    }
}

/* translation */
addr_t v2p_nopae (vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    page_info_t *info)
{

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: lookup vaddr = 0x%.16"PRIx64", dtb = 0x%.16"PRIx64"\n", vaddr, dtb);
    info->x86_legacy.pgd_value = get_pgd_nopae(vmi, vaddr, dtb, &info->x86_legacy.pgd_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd = 0x%.8"PRIx32"\n", info->x86_legacy.pgd_value);

    if (!ENTRY_PRESENT(vmi->os_type, info->x86_legacy.pgd_value)) {
        buffalo_nopae(vmi, info->x86_legacy.pgd_value, 0);
        goto done;
    }

    if (PAGE_SIZE(info->x86_legacy.pgd_value) && (VMI_FILE == vmi->mode || vmi->pse)) {
        info->paddr = get_large_paddr_nopae(vaddr, info->x86_legacy.pgd_value);
        info->size = VMI_PS_4MB;
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 4MB page 0x%"PRIx32"\n", info->x86_legacy.pgd_value);
        goto done;
    }

    info->x86_legacy.pte_value = get_pte_nopae(vmi, vaddr, info->x86_legacy.pgd_value, &info->x86_legacy.pte_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte = 0x%.8"PRIx32"\n", info->x86_legacy.pte_value);

    if (!ENTRY_PRESENT(vmi->os_type, info->x86_legacy.pte_value)) {
        buffalo_nopae(vmi, info->x86_legacy.pte_value, 1);
        goto done;
    }

    info->size = VMI_PS_4KB;
    info->paddr = get_paddr_nopae(vaddr, info->x86_legacy.pte_value);
    goto done;

done:
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: paddr = 0x%.16"PRIx64"\n", info->paddr);
    return info->paddr;
}

addr_t v2p_pae (vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    page_info_t *info)
{

    dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: lookup vaddr = 0x%.16"PRIx64" dtb = 0x%.16"PRIx64"\n", vaddr, dtb);
    info->x86_pae.pdpe_value = get_pdpi(vmi, vaddr, dtb, &info->x86_pae.pdpe_location);

    if(!info->x86_pae.pdpe_value) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: failed to read pdpe\n");
        goto done;
    }

    dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: pdpe = 0x%"PRIx64"\n", info->x86_pae.pdpe_value);

    if (!ENTRY_PRESENT(vmi->os_type, info->x86_pae.pdpe_value)) {
        goto done;
    }

    info->x86_pae.pgd_value = get_pgd_pae(vmi, vaddr, info->x86_pae.pdpe_value, &info->x86_pae.pgd_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: pgd = 0x%.16"PRIx64"\n", info->x86_pae.pgd_value);

    if (!ENTRY_PRESENT(vmi->os_type, info->x86_pae.pgd_value)) {
        goto done;
    }

    if (PAGE_SIZE(info->x86_pae.pgd_value)) {
        info->paddr = get_large_paddr_pae(vaddr, info->x86_pae.pgd_value);
        info->size = VMI_PS_2MB;
        dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: 2MB page\n");
        goto done;
    }

    info->x86_pae.pte_value = get_pte_pae(vmi, vaddr, info->x86_pae.pgd_value, &info->x86_pae.pte_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: pte = 0x%.16"PRIx64"\n", info->x86_pae.pte_value);
    if (!ENTRY_PRESENT(vmi->os_type, info->x86_pae.pte_value)) {
        goto done;
    }

    info->size = VMI_PS_4KB;
    info->paddr = get_paddr_pae(vaddr, info->x86_pae.pte_value);

done:
    dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: paddr = 0x%.16"PRIx64"\n", info->paddr);
    return info->paddr;
}

GSList* get_va_pages_nopae(vmi_instance_t vmi, addr_t dtb) {

    #define PTRS_PER_PTE 1024
    #define PTRS_PER_PGD 1024

    addr_t pgd_curr = dtb;
    uint8_t entry_size = 0x4;

    GSList *ret = NULL;

    uint32_t j;
    for(j=0;j<PTRS_PER_PGD;j++,pgd_curr+=entry_size) {
        uint64_t soffset = j * PTRS_PER_PGD * PTRS_PER_PTE * entry_size;

        uint32_t entry;
        if(VMI_FAILURE == vmi_read_32_pa(vmi, pgd_curr, &entry)) {
            continue;
        }

        if(ENTRY_PRESENT(vmi->os_type, entry)) {

            if(PAGE_SIZE(entry) && (VMI_FILE == vmi->mode || vmi->pse)) {
                page_info_t *p = g_malloc0(sizeof(page_info_t));
                p->vaddr = soffset;
                p->paddr = get_large_paddr_nopae(p->vaddr, soffset);
                p->size = VMI_PS_4MB;
                p->x86_legacy.pgd_location = pgd_curr;
                p->x86_legacy.pgd_value = entry;
                ret = g_slist_prepend(ret, p);
                continue;
            }

            uint32_t pte_curr = entry & ~(0xFFF);

            uint32_t k;
            for(k=0;k<PTRS_PER_PTE;k++,pte_curr+=entry_size){
                uint32_t pte_entry;
                if(VMI_FAILURE == vmi_read_32_pa(vmi, pte_curr, &pte_entry)) {
                    continue;
                }

                if(ENTRY_PRESENT(vmi->os_type, pte_entry)) {
                    page_info_t *p = g_malloc0(sizeof(page_info_t));
                    p->vaddr = soffset + k * VMI_PS_4KB;
                    p->paddr = get_paddr_nopae(p->vaddr, pte_entry);
                    p->size = VMI_PS_4KB;
                    p->x86_legacy.pgd_location = pgd_curr;
                    p->x86_legacy.pgd_value = entry;
                    p->x86_legacy.pte_location = pte_curr;
                    p->x86_legacy.pte_value = pte_entry;
                    ret = g_slist_prepend(ret, p);
                }
            }
        }
    }

    return ret;
}

GSList* get_va_pages_pae(vmi_instance_t vmi, addr_t dtb) {

    uint32_t pdpi_base = get_pdptb(dtb);
    uint8_t entry_size = 0x8;

    GSList *ret = NULL;

    uint32_t i;
    for(i=0;i<PTRS_PER_PDPI;i++) {

        uint32_t start = i * PTRS_PER_PAE_PGD * PTRS_PER_PAE_PGD * PTRS_PER_PAE_PTE * entry_size;
        uint32_t pdpi_entry = pdpi_base + i * entry_size;

        uint64_t pdpe;
        vmi_read_64_pa(vmi, pdpi_entry, &pdpe);

        if(!ENTRY_PRESENT(vmi->os_type, pdpe)) {
            continue;
        }

        uint64_t pgd_curr = pdba_base_pae(pdpe);

        uint32_t j;
        for(j=0;j<PTRS_PER_PAE_PGD;j++,pgd_curr+=entry_size) {
            uint64_t soffset = start + (j * PTRS_PER_PAE_PGD * PTRS_PER_PAE_PTE * entry_size);

            uint64_t entry;
            if(VMI_FAILURE == vmi_read_64_pa(vmi, pgd_curr, &entry)) {
                continue;
            }

            if(ENTRY_PRESENT(vmi->os_type, entry)) {

                if(PAGE_SIZE(entry)) {
                    page_info_t *p = g_malloc0(sizeof(page_info_t));
                    p->vaddr = soffset;
                    p->paddr = get_large_paddr_pae(p->vaddr, pgd_curr);
                    p->size = VMI_PS_2MB;
                    p->x86_pae.pdpe_location = pdpi_entry;
                    p->x86_pae.pdpe_value = pdpe;
                    p->x86_pae.pgd_location = pgd_curr;
                    p->x86_pae.pgd_value = entry;
                    ret = g_slist_prepend(ret, p);
                    continue;
                }

                uint64_t pte_curr = entry & ~(0xFFF);
                uint32_t k;
                for(k=0;k<PTRS_PER_PAE_PTE;k++,pte_curr+=entry_size){
                    uint64_t pte_entry;
                    if(VMI_FAILURE == vmi_read_64_pa(vmi, pte_curr, &pte_entry)) {
                        continue;
                    }

                    if(ENTRY_PRESENT(vmi->os_type, pte_entry)) {
                        page_info_t *p = g_malloc0(sizeof(page_info_t));
                        p->vaddr = soffset + k * VMI_PS_4KB;
                        p->paddr = get_paddr_pae(p->vaddr, pte_entry);
                        p->size = VMI_PS_4KB;
                        p->x86_pae.pdpe_location = pdpi_entry;
                        p->x86_pae.pdpe_value = pdpe;
                        p->x86_pae.pgd_location = pgd_curr;
                        p->x86_pae.pgd_value = entry;
                        p->x86_pae.pte_location = pte_curr;
                        p->x86_pae.pte_value = pte_entry;
                        ret = g_slist_prepend(ret, p);
                    }
                }
            }
        }
    }

    return ret;
}

status_t intel_init(vmi_instance_t vmi) {

    status_t ret = VMI_SUCCESS;

    if(!vmi->arch_interface) {
        vmi->arch_interface = safe_malloc(sizeof(struct arch_interface));
        bzero(vmi->arch_interface, sizeof(struct arch_interface));
    }

    if(vmi->page_mode == VMI_PM_LEGACY) {
        vmi->arch_interface->v2p = v2p_nopae;
        vmi->arch_interface->get_va_pages = get_va_pages_nopae;
    } else if(vmi->page_mode == VMI_PM_PAE) {
        vmi->arch_interface->v2p = v2p_pae;
        vmi->arch_interface->get_va_pages = get_va_pages_pae;
    } else {
        ret = VMI_FAILURE;
        free(vmi->arch_interface);
        vmi->arch_interface = NULL;
    }

    return ret;
}

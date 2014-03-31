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

/* "buffalo" routines
 * see "Using Every Part of the Buffalo in Windows Memory Analysis" by
 * Jesse D. Kornblum for details. */
#define GET_TRANSITION_BIT(entry) VMI_GET_BIT(entry, 11)
#define GET_PROTOTYPE_BIT(entry) VMI_GET_BIT(entry, 10)

/* page directory pointer table */
static inline
uint64_t get_pdptb (uint64_t pdpr)
{
    return pdpr & 0xFFFFFFFFFFFFFFE0UL;
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
    return (((address) >> 22) & 0x3FFUL) * sizeof(uint32_t);
}

static inline
uint32_t pgd_index_pae (uint32_t address)
{
    return (((address) >> 21) & 0x1FFUL) * sizeof(uint64_t);
}

static inline
uint32_t pdba_base_nopae (uint32_t pdpe)
{
    return pdpe & 0xFFFFF000UL;
}

static inline
uint64_t pdba_base_pae (uint64_t pdpe)
{
    return pdpe & 0xFFFFFFFFFF000ULL;
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
    return (((address) >> 12) & 0x3FFUL) * sizeof(uint32_t);
}

static inline
uint32_t pte_index_pae (uint32_t address)
{
    return (((address) >> 12) & 0x1FFUL) * sizeof(uint64_t);
}

static inline
uint32_t ptba_base_nopae (uint32_t pde)
{
    return pde & 0xFFFFF000UL;
}

static inline
uint64_t ptba_base_pae (uint64_t pde)
{
    return pde & 0xFFFFFF000ULL;
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
    return pte & 0xFFFFF000UL;
}

static inline
uint64_t pte_pfn_pae (uint64_t pte)
{
    return pte & 0xFFFFFF000ULL;
}

static inline
uint32_t get_paddr_nopae (uint32_t vaddr, uint32_t pte)
{
    return pte_pfn_nopae(pte) | (vaddr & 0xFFFUL);
}

static inline
uint64_t get_paddr_pae (uint32_t vaddr, uint64_t pte)
{
    return pte_pfn_pae(pte) | (vaddr & 0xFFFUL);
}

static inline
uint32_t get_large_paddr_nopae (uint32_t vaddr, uint32_t pgd_entry)
{
    return (pgd_entry & 0xFFC00000UL) | (vaddr & 0x3FFFFFUL);
}

static inline
uint32_t get_large_paddr_pae (uint32_t vaddr, uint32_t pgd_entry)
{
    return (pgd_entry & 0xFFE00000UL) | (vaddr & 0x1FFFFFUL);
}

void buffalo_nopae (vmi_instance_t instance, uint32_t entry, int pde)
{
    /* similar techniques are surely doable in linux, but for now
     * this is only testing for windows domains */
    if (!instance->os_type == VMI_OS_WINDOWS) {
        return;
    }

    if (!GET_TRANSITION_BIT(entry) && !GET_PROTOTYPE_BIT(entry)) {
        uint32_t pfnum = (entry >> 1) & 0xF;
        uint32_t pfframe = entry & 0xFFFFF000UL;

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

    else if (GET_TRANSITION_BIT(entry) && !GET_PROTOTYPE_BIT(entry)) {
        /* transition */
        dbprint(VMI_DEBUG_PTLOOKUP, "--Buffalo: page in transition\n");
    }

    else if (!pde && GET_PROTOTYPE_BIT(entry)) {
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

    addr_t pgd = 0, pte = 0;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: lookup vaddr = 0x%.16"PRIx64", dtb = 0x%.16"PRIx64"\n", vaddr, dtb);
    pgd = get_pgd_nopae(vmi, vaddr, dtb, &info->l2_a);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd = 0x%.8"PRIx32"\n", pgd);

    if (ENTRY_PRESENT(vmi->os_type, pgd)) {
        info->l2_v = pgd;
        if (PAGE_SIZE_FLAG(pgd)) {
            info->paddr = get_large_paddr_nopae(vaddr, pgd);
            info->size = VMI_PS_4MB;
            dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 4MB page 0x%"PRIx32"\n", pgd);
        }
        else {
            pte = get_pte_nopae(vmi, vaddr, pgd, &info->l1_a);
            dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte = 0x%.8"PRIx32"\n", pte);
            if (ENTRY_PRESENT(vmi->os_type, pte)) {
                info->l1_v = pte;
                info->size = VMI_PS_4KB;
                info->paddr = get_paddr_nopae(vaddr, pte);
            }
            else {
                buffalo_nopae(vmi, pte, 1);
            }
        }
    }
    else {
        buffalo_nopae(vmi, pgd, 0);
    }
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: paddr = 0x%.16"PRIx64"\n", info->paddr);
    return info->paddr;
}

addr_t v2p_pae (vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    page_info_t *info)
{
    uint64_t pdpe = 0, pgd = 0, pte = 0;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: lookup vaddr = 0x%.16"PRIx64" dtb = 0x%.16"PRIx64"\n", vaddr, dtb);
    pdpe = get_pdpi(vmi, vaddr, dtb, &info->l3_a);

    if(!pdpe) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: failed to read pdpe\n");
        goto done;
    }

    dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: pdpe = 0x%"PRIx64"\n", pdpe);

    if (!ENTRY_PRESENT(vmi->os_type, pdpe)) {
        goto done;
    }
    info->l3_v = pdpe;

    pgd = get_pgd_pae(vmi, vaddr, pdpe, &info->l2_a);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: pgd = 0x%.16"PRIx64"\n", pgd);

    if (ENTRY_PRESENT(vmi->os_type, pgd)) {
        info->l2_v = pgd;
        if (PAGE_SIZE_FLAG(pgd)) {
            info->paddr = get_large_paddr_pae(vaddr, pgd);
            info->size = VMI_PS_2MB;
            dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: 2MB page\n");
        }
        else {
            pte = get_pte_pae(vmi, vaddr, pgd, &info->l1_a);
            dbprint(VMI_DEBUG_PTLOOKUP, "--PAE PTLookup: pte = 0x%.16"PRIx64"\n", pte);
            if (ENTRY_PRESENT(vmi->os_type, pte)) {
                info->l1_v = pte;
                info->size = VMI_PS_4KB;
                info->paddr = get_paddr_pae(vaddr, pte);
            }
        }
    }

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

            if(PAGE_SIZE_FLAG(entry)) {
                struct va_page *p = g_malloc0(sizeof(struct va_page));
                p->va = soffset;
                p->size = VMI_PS_4MB;
                ret = g_slist_append(ret, p);
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
                    struct va_page *p = g_malloc0(sizeof(struct va_page));
                    p->va = soffset + k * VMI_PS_4KB;
                    p->size = VMI_PS_4KB;
                    ret = g_slist_append(ret, p);
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

                if(PAGE_SIZE_FLAG(entry)) {
                    struct va_page *p = g_malloc0(sizeof(struct va_page));
                    p->va = soffset;
                    p->size = VMI_PS_2MB;
                    ret = g_slist_append(ret, p);
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
                        struct va_page *p = g_malloc0(sizeof(struct va_page));
                        p->va = soffset + k * VMI_PS_4KB;
                        p->size = VMI_PS_4KB;
                        ret = g_slist_append(ret, p);
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

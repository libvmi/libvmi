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
#include <stdlib.h>
#include <sys/mman.h>

/* bit flag testing */
int entry_present (os_t os_type, uint64_t entry)
{
    if (vmi_get_bit(entry, 0))
        return 1;
    /* Support Windows "Transition" pages (bit 11) and not "Prototype PTE" (bit 10)
     * pages on Windows.  See http://code.google.com/p/vmitools/issues/detail?id=35
     */
    if (os_type == VMI_OS_WINDOWS
            && (vmi_get_bit(entry, 11) && !(vmi_get_bit(entry, 10))))
        return 1;
    return 0;
}

int page_size_flag (uint64_t entry)
{

    return vmi_get_bit(entry, 7);
}

/* utility bit grabbing functions */
uint64_t get_bits_51to12 (uint64_t value)
{
    return value & 0x000FFFFFFFFFF000ULL;
}

/* PML4 Table  */
addr_t get_pml4_index (addr_t vaddr)
{
    return (vaddr & 0x0000FF8000000000ULL) >> 36;
}

uint64_t get_pml4e (vmi_instance_t vmi,
    addr_t vaddr,
    reg_t cr3,
    addr_t *pml4e_address)
{
    uint64_t value = 0;
    *pml4e_address = get_bits_51to12(cr3) | get_pml4_index(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup pml4e_address = 0x%.16"PRIx64"\n", *pml4e_address);
    vmi_read_64_pa(vmi, *pml4e_address, &value);
    return value;
}

/* page directory pointer table */
uint64_t get_pdptb (uint64_t pdpr)
{
    return pdpr & 0xFFFFFFFFFFFFFFE0;
}

uint32_t pdpi_index (uint32_t pdpi)
{
    return (pdpi >> 30) * sizeof(uint64_t);
}

uint64_t get_pdpi (vmi_instance_t instance,
    uint32_t vaddr,
    addr_t cr3,
    addr_t *pdpi_entry)
{
    uint64_t value;
    *pdpi_entry = get_pdptb(cr3) + pdpi_index(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpi_entry = 0x%.8x\n", *pdpi_entry);
    vmi_read_64_pa(instance, *pdpi_entry, &value);
    return value;
}

addr_t get_pdpt_index_ia32e (addr_t vaddr)
{
    return (vaddr & 0x0000007FC0000000ULL) >> 27;
}

uint64_t get_pdpte_ia32e (vmi_instance_t vmi,
    addr_t vaddr,
    uint64_t pml4e,
    addr_t *pdpte_address)
{
    uint64_t value = 0;
    *pdpte_address = get_bits_51to12(pml4e) | get_pdpt_index_ia32e(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpte_address = 0x%.16"PRIx64"\n", *pdpte_address);
    vmi_read_64_pa(vmi, *pdpte_address, &value);
    return value;
}

/* page directory */
uint32_t pgd_index (vmi_instance_t instance, uint32_t address)
{
    if (!instance->pae) {
        return (((address) >> 22) & 0x3FF) * sizeof(uint32_t);
    }
    else {
        return (((address) >> 21) & 0x1FF) * sizeof(uint64_t);
    }
}

uint32_t pdba_base_nopae (uint32_t pdpe)
{
    return pdpe & 0xFFFFF000;
}

uint64_t pdba_base_pae (uint64_t pdpe)
{
    return pdpe & 0xFFFFFF000ULL;
}

uint64_t pdba_base_ia32e (uint64_t pdpe)
{
    return get_bits_51to12(pdpe);
}

uint32_t get_pgd_nopae (vmi_instance_t instance,
    uint32_t vaddr,
    uint32_t pdpe,
    addr_t *pgd_entry)
{
    uint32_t value;
    *pgd_entry = pdba_base_nopae(pdpe) + pgd_index(instance, vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd_entry = 0x%.8x\n", *pgd_entry);
    vmi_read_32_pa(instance, *pgd_entry, &value);
    return value;
}

uint64_t get_pgd_pae (vmi_instance_t instance,
    uint32_t vaddr,
    uint64_t pdpe,
    addr_t *pgd_entry)
{
    uint64_t value;
    *pgd_entry = pdba_base_pae(pdpe) + pgd_index(instance, vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd_entry = 0x%.8x\n", *pgd_entry);
    vmi_read_64_pa(instance, *pgd_entry, &value);
    return value;
}

uint64_t get_pd_index_ia32e (addr_t vaddr)
{
    return (vaddr & 0x000000003FE00000ULL) >> 18;
}

uint64_t get_pde_ia32e (vmi_instance_t vmi,
    addr_t vaddr,
    uint64_t pdpte,
    addr_t *pde_address)
{
    uint64_t value = 0;
    *pde_address = get_bits_51to12(pdpte) | get_pd_index_ia32e(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pde_address = 0x%.16"PRIx64"\n", *pde_address);
    vmi_read_64_pa(vmi, *pde_address, &value);
    return value;
}

/* page table */
uint32_t pte_index (vmi_instance_t instance, uint32_t address)
{
    if (!instance->pae) {
        return (((address) >> 12) & 0x3FF) * sizeof(uint32_t);
    }
    else {
        return (((address) >> 12) & 0x1FF) * sizeof(uint64_t);
    }
}

uint32_t ptba_base_nopae (uint32_t pde)
{
    return pde & 0xFFFFF000;
}

uint64_t ptba_base_pae (uint64_t pde)
{
    return pde & 0xFFFFFF000ULL;
}

uint32_t get_pte_nopae (vmi_instance_t instance,
    uint32_t vaddr,
    uint32_t pgd,
    addr_t *pte_entry)
{
    uint32_t value;
    *pte_entry = ptba_base_nopae(pgd) + pte_index(instance, vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_entry = 0x%.8x\n", *pte_entry);
    vmi_read_32_pa(instance, *pte_entry, &value);
    return value;
}

uint64_t get_pte_pae (vmi_instance_t instance,
    uint32_t vaddr,
    uint64_t pgd,
    addr_t *pte_entry)
{
    uint64_t value;
    *pte_entry = ptba_base_pae(pgd) + pte_index(instance, vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_entry = 0x%.8x\n", *pte_entry);
    vmi_read_64_pa(instance, *pte_entry, &value);
    return value;
}

uint64_t get_pt_index_ia32e (addr_t vaddr)
{
    return (vaddr & 0x00000000001FF000ULL) >> 9;
}

uint64_t get_pte_ia32e (vmi_instance_t vmi,
    addr_t vaddr,
    uint64_t pde,
    addr_t *pte_address)
{
    uint64_t value = 0;
    *pte_address = get_bits_51to12(pde) | get_pt_index_ia32e(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_address = 0x%.16"PRIx64"\n", *pte_address);
    vmi_read_64_pa(vmi, *pte_address, &value);
    return value;
}

/* page */
uint32_t pte_pfn_nopae (uint32_t pte)
{
    return pte & 0xFFFFF000;
}

uint64_t pte_pfn_pae (uint64_t pte)
{
    return pte & 0xFFFFFF000ULL;
}

uint64_t pte_pfn_ia32e (uint64_t pte)
{
    return get_bits_51to12(pte);
}

uint32_t get_paddr_nopae (uint32_t vaddr, uint32_t pte)
{
    return pte_pfn_nopae(pte) | (vaddr & 0xFFF);
}

uint64_t get_paddr_pae (uint32_t vaddr, uint64_t pte)
{
    return pte_pfn_pae(pte) | (vaddr & 0xFFF);
}

uint64_t get_paddr_ia32e (addr_t vaddr, uint64_t pte)
{
    return get_bits_51to12(pte) | (vaddr & 0x0000000000000FFFULL);
}

uint32_t get_large_paddr (vmi_instance_t instance, uint32_t vaddr,
        uint32_t pgd_entry)
{
    if (!instance->pae) {
        return (pgd_entry & 0xFFC00000) | (vaddr & 0x3FFFFF);
    }
    else {
        return (pgd_entry & 0xFFE00000) | (vaddr & 0x1FFFFF);
    }
}

uint64_t get_gigpage_ia32e (addr_t vaddr, uint64_t pdpte)
{
    return (pdpte & 0x000FFFFFC0000000ULL) | (vaddr & 0x000000003FFFFFFFULL);
}

uint64_t get_2megpage_ia32e (addr_t vaddr, uint64_t pde)
{
    return (pde & 0x000FFFFFFFE00000ULL) | (vaddr & 0x00000000001FFFFFULL);
}

/* "buffalo" routines
 * see "Using Every Part of the Buffalo in Windows Memory Analysis" by
 * Jesse D. Kornblum for details.
 * for now, just test the bits and print out details */
int get_transition_bit (uint32_t entry)
{
    return vmi_get_bit(entry, 11);
}

int get_prototype_bit (uint32_t entry)
{
    return vmi_get_bit(entry, 10);
}

void buffalo_nopae (vmi_instance_t instance, uint32_t entry, int pde)
{
    /* similar techniques are surely doable in linux, but for now
     * this is only testing for windows domains */
    if (!instance->os_type == VMI_OS_WINDOWS) {
        return;
    }

    if (!get_transition_bit(entry) && !get_prototype_bit(entry)) {
        uint32_t pfnum = (entry >> 1) & 0xF;
        uint32_t pfframe = entry & 0xFFFFF000;

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

    else if (get_transition_bit(entry) && !get_prototype_bit(entry)) {
        /* transition */
        dbprint(VMI_DEBUG_PTLOOKUP, "--Buffalo: page in transition\n");
    }

    else if (!pde && get_prototype_bit(entry)) {
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

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: lookup vaddr = 0x%.16"PRIx64"\n", vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: dtb = 0x%.16"PRIx64"\n", dtb);
    pgd = get_pgd_nopae(vmi, vaddr, dtb, &info->l2_a);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd = 0x%.8"PRIx32"\n", pgd);

    if (entry_present(vmi->os_type, pgd)) {
        info->l2_v = pgd;
        if (page_size_flag(pgd)) {
            info->paddr = get_large_paddr(vmi, vaddr, pgd);
            info->size = VMI_PS_4MB;
            dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 4MB page 0x%"PRIx32"\n", pgd);
        }
        else {
            pte = get_pte_nopae(vmi, vaddr, pgd, &info->l1_a);
            dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte = 0x%.8"PRIx32"\n", pte);
            if (entry_present(vmi->os_type, pte)) {
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
    uint64_t pdpe, pgd, pte;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: lookup vaddr = 0x%.16"PRIx64"\n", vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: dtb = 0x%.16"PRIx64"\n", dtb);
    pdpe = get_pdpi(vmi, vaddr, dtb, &info->l3_a);

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpe = 0x%.16"PRIx64"\n", pdpe);
    if (!entry_present(vmi->os_type, pdpe)) {
        goto done;
    }
    info->l3_v = pdpe;

    pgd = get_pgd_pae(vmi, vaddr, pdpe, &info->l2_a);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd = 0x%.16"PRIx64"\n", pgd);

    if (entry_present(vmi->os_type, pgd)) {
        info->l2_v = pgd;
        if (page_size_flag(pgd)) {
            info->paddr = get_large_paddr(vmi, vaddr, pgd);
            info->size = VMI_PS_2MB;
            dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 2MB page\n");
        }
        else {
            pte = get_pte_pae(vmi, vaddr, pgd, &info->l1_a);
            dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte = 0x%.16"PRIx64"\n", pte);
            if (entry_present(vmi->os_type, pte)) {
                info->l1_v = pte;
                info->size = VMI_PS_4KB;
                info->paddr = get_paddr_pae(vaddr, pte);
            }
        }
    }

done:
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: paddr = 0x%.16"PRIx64"\n", info->paddr);
    return info->paddr;
}

addr_t v2p_ia32e (vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    page_info_t *info)
{
    uint64_t pml4e = 0, pdpte = 0, pde = 0, pte = 0;

    // are we in compatibility mode OR 64-bit mode ???

    // validate address based on above (e.g., is it canonical?)

    // determine what MAXPHYADDR is

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: lookup vaddr = 0x%.16"PRIx64"\n", vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: dtb = 0x%.16"PRIx64"\n", dtb);
    pml4e = get_pml4e(vmi, vaddr, dtb, &info->l4_a);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pml4e = 0x%.16"PRIx64"\n", pml4e);

    if (entry_present(vmi->os_type, pml4e)) {
        info->l4_v = pml4e;

        pdpte = get_pdpte_ia32e(vmi, vaddr, pml4e, &info->l3_a);
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpte = 0x%.16"PRIx64"\n", pdpte);

        if (entry_present(vmi->os_type, pdpte)) {
            info->l3_v = pdpte;
            if (page_size_flag(pdpte)) { // pdpte maps a 1GB page
                info->paddr = get_gigpage_ia32e(vaddr, pdpte);
                info->size = VMI_PS_1GB;
                dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 1GB page\n");
            }
            else {
                pde = get_pde_ia32e(vmi, vaddr, pdpte, &info->l2_a);
                dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pde = 0x%.16"PRIx64"\n", pde);
            }

            if (entry_present(vmi->os_type, pde)) {
                info->l2_v = pde;
                if (page_size_flag(pde)) { // pde maps a 2MB page
                    info->paddr = get_2megpage_ia32e(vaddr, pde);
                    info->size = VMI_PS_2MB;
                    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 2MB page\n");
                }
                else {
                    pte = get_pte_ia32e(vmi, vaddr, pde, &info->l1_a);
                    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte = 0x%.16"PRIx64"\n", pte);
                }

                if (entry_present(vmi->os_type, pte)) {
                    info->l1_v = pte;
                    info->size = VMI_PS_4KB;
                    info->paddr = get_paddr_ia32e(vaddr, pte);
                }
            }
        }
    }

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: paddr = 0x%.16"PRIx64"\n", info->paddr);
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

        if(entry_present(vmi->os_type, entry)) {

            if(page_size_flag(entry)) {
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

                if(entry_present(vmi->os_type, pte_entry)) {
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

    #define PTRS_PER_PDPI 4
    #define PTRS_PER_PAE_PTE 512
    #define PTRS_PER_PAE_PGD 512

    uint32_t pdpi_base = get_pdptb(dtb);
    uint8_t entry_size = 0x8;

    GSList *ret = NULL;

    uint32_t i;
    for(i=0;i<PTRS_PER_PDPI;i++) {

        uint32_t start = i * PTRS_PER_PAE_PGD * PTRS_PER_PAE_PGD * PTRS_PER_PAE_PTE * entry_size;
        uint32_t pdpi_entry = pdpi_base + i * entry_size;

        uint64_t pdpe;
        vmi_read_64_pa(vmi, pdpi_entry, &pdpe);

        if(!entry_present(vmi->os_type, pdpe)) {
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

            if(entry_present(vmi->os_type, entry)) {

                if(page_size_flag(entry)) {
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

                    if(entry_present(vmi->os_type, pte_entry)) {
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

GSList* get_va_pages_ia32e(vmi_instance_t vmi, addr_t dtb) {

    GSList *ret = NULL;
    uint8_t entry_size = 0x8;

    #define PDES_AND_PTES_PER_PAGE 0x200 // 0x1000/0x8

    uint64_t pml4e;
    for(pml4e=0;pml4e<PDES_AND_PTES_PER_PAGE;pml4e++) {

        addr_t vaddr = pml4e << 39;
        addr_t pml4e_a = 0;
        uint64_t pml4e_value = get_pml4e(vmi, vaddr, dtb, &pml4e_a);

        if(!entry_present(vmi->os_type, pml4e_value)) {
            continue;
        }

        uint64_t pdpte;
        for(pdpte=0;pdpte<PDES_AND_PTES_PER_PAGE;pdpte++) {

            vaddr = (pml4e << 39) | (pdpte << 30);

            addr_t pdpte_a = 0;
            uint64_t pdpte_value = get_pdpte_ia32e(vmi, vaddr, pml4e_value, &pdpte_a);
            if(!entry_present(vmi->os_type, pdpte_value)) {
                continue;
            }

            if(page_size_flag(pdpte_value)) {
                struct va_page *p = g_malloc0(sizeof(struct va_page));
                p->va = vaddr;
                p->size = VMI_PS_1GB;
                ret = g_slist_append(ret, p);
                continue;
            }

            uint64_t pgd_curr = pdba_base_ia32e(pdpte_value);
            uint64_t j;
            for(j=0;j<PTRS_PER_PAE_PGD;j++,pgd_curr+=entry_size) {

                uint64_t soffset = vaddr + (j * PTRS_PER_PAE_PGD * PTRS_PER_PAE_PTE * entry_size);

                uint64_t entry;
                if(VMI_FAILURE == vmi_read_64_pa(vmi, pgd_curr, &entry)) {
                    continue;
                }

                if(entry_present(vmi->os_type, entry)) {

                    if(page_size_flag(entry)) {
                        struct va_page *p = g_malloc0(sizeof(struct va_page));
                        p->va = soffset;
                        p->size = VMI_PS_2MB;
                        ret = g_slist_append(ret, p);
                        continue;
                    }

                    uint64_t pte_curr = pte_pfn_ia32e(entry);
                    uint64_t k;
                    for(k=0;k<PTRS_PER_PAE_PTE;k++,pte_curr+=entry_size) {
                        uint64_t pte_entry;
                        if(VMI_FAILURE == vmi_read_64_pa(vmi, pte_curr, &pte_entry)) {
                            continue;
                        }

                        if(entry_present(vmi->os_type, pte_entry)) {
                            struct va_page *p = g_malloc0(sizeof(struct va_page));
                            p->va = soffset + k * VMI_PS_4KB;
                            p->size = VMI_PS_4KB;
                            ret = g_slist_append(ret, p);
                            continue;
                        }
                    }
                }
            }
        }
    }

    return ret;
}

GSList* vmi_get_va_pages(vmi_instance_t vmi, addr_t dtb) {

    GSList *ret = NULL;

    if (vmi->page_mode == VMI_PM_LEGACY) {
        ret = get_va_pages_nopae(vmi, dtb);
    } else if (vmi->page_mode == VMI_PM_PAE) {
        ret = get_va_pages_pae(vmi, dtb);
    } else if (vmi->page_mode == VMI_PM_IA32E) {
        ret = get_va_pages_ia32e(vmi, dtb);
    }

    return ret;
}

addr_t vmi_pagetable_lookup (vmi_instance_t vmi, addr_t dtb, addr_t vaddr)
{

    page_info_t info = {0};

    /* check if entry exists in the cachec */
    if (VMI_SUCCESS == v2p_cache_get(vmi, vaddr, dtb, &info.paddr)) {

        /* verify that address is still valid */
        uint8_t value = 0;

        if (VMI_SUCCESS == vmi_read_8_pa(vmi, info.paddr, &value)) {
            return info.paddr;
        }
        else {
            v2p_cache_del(vmi, vaddr, dtb);
        }
    }

    /* do the actual page walk in guest memory */
    if (vmi->page_mode == VMI_PM_LEGACY) {
        v2p_nopae(vmi, dtb, vaddr, &info);
    }
    else if (vmi->page_mode == VMI_PM_PAE) {
        v2p_pae(vmi, dtb, vaddr, &info);
    }
    else if (vmi->page_mode == VMI_PM_IA32E) {
        v2p_ia32e(vmi, dtb, vaddr, &info);
    }
    else {
        errprint("Invalid paging mode during vmi_pagetable_lookup\n");
    }

    /* add this to the cache */
    if (info.paddr) {
        v2p_cache_set(vmi, vaddr, dtb, info.paddr);
    }
    return info.paddr;
}

status_t vmi_pagetable_lookup_extended(
    vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    page_info_t *info)
{
    status_t ret = VMI_FAILURE;

    if(!info) return ret;

    memset(info, 0, sizeof(page_info_t));
    info->vaddr = vaddr;
    info->dtb = dtb;

    if (vmi->page_mode == VMI_PM_LEGACY) {
        v2p_nopae(vmi, dtb, vaddr, info);
    }
    else if (vmi->page_mode == VMI_PM_PAE) {
        v2p_pae(vmi, dtb, vaddr, info);
    }
    else if (vmi->page_mode == VMI_PM_IA32E) {
        v2p_ia32e(vmi, dtb, vaddr, info);
    }
    else {
        errprint("Invalid paging mode during vmi_pagetable_lookup_extended\n");
    }

    if(info->paddr) {
        ret = VMI_SUCCESS;
    }

    return ret;
}

/* expose virtual to physical mapping for kernel space via api call */
addr_t vmi_translate_kv2p (vmi_instance_t vmi, addr_t virt_address)
{
    reg_t cr3 = 0;

    if (vmi->kpgd) {
        cr3 = vmi->kpgd;
    } else {
        driver_get_vcpureg(vmi, &cr3, CR3, 0);
    }
    if (!cr3) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--early bail on v2p lookup because cr3 is zero\n");
        return 0;
    }
    else {
        return vmi_pagetable_lookup(vmi, cr3, virt_address);
    }
}

/* expose virtual to physical mapping for user space via api call */
addr_t vmi_translate_uv2p_nocache (vmi_instance_t vmi, addr_t virt_address,
        vmi_pid_t pid)
{
    addr_t dtb = vmi_pid_to_dtb(vmi, pid);

    if (!dtb) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--early bail on v2p lookup because dtb is zero\n");
        return 0;
    }
    else {
        addr_t rtnval = vmi_pagetable_lookup(vmi, dtb, virt_address);

        if (!rtnval) {
            pid_cache_del(vmi, pid);
        }
        return rtnval;
    }
}

addr_t vmi_translate_uv2p (vmi_instance_t vmi, addr_t virt_address, vmi_pid_t pid)
{
    addr_t dtb = vmi_pid_to_dtb(vmi, pid);

    if (!dtb) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--early bail on v2p lookup because dtb is zero\n");
        return 0;
    }
    else {
        addr_t rtnval = vmi_pagetable_lookup(vmi, dtb, virt_address);

        if (!rtnval) {
            if (VMI_SUCCESS == pid_cache_del(vmi, pid)) {
                return vmi_translate_uv2p_nocache(vmi, virt_address, pid);
            }
        }
        return rtnval;
    }
}

/* convert a kernel symbol into an address */
addr_t vmi_translate_ksym2v (vmi_instance_t vmi, const char *symbol)
{
    status_t status = VMI_FAILURE;
    addr_t base_vaddr = 0;
    addr_t address = 0;

    if (VMI_FAILURE == sym_cache_get(vmi, base_vaddr, 0, symbol, &address)) {

        if (vmi->os_interface && vmi->os_interface->os_ksym2v) {
            status = vmi->os_interface->os_ksym2v(vmi, symbol, &base_vaddr,
                    &address);
            if (status == VMI_SUCCESS) {
                sym_cache_set(vmi, base_vaddr, 0, symbol, address);
            }
        }
    }

    return address;
}

/* convert a symbol into an address */
addr_t vmi_translate_sym2v (vmi_instance_t vmi, addr_t base_vaddr, vmi_pid_t pid, char *symbol)
{
    status_t status = VMI_FAILURE;
    addr_t rva = 0;
    addr_t address = 0;

    if (VMI_FAILURE == sym_cache_get(vmi, base_vaddr, pid, symbol, &address)) {

        if (vmi->os_interface && vmi->os_interface->os_usym2rva) {
            status  = vmi->os_interface->os_usym2rva(vmi, base_vaddr, pid, symbol, &rva);
            if (status == VMI_SUCCESS) {
                address = base_vaddr + rva;
                sym_cache_set(vmi, base_vaddr, pid, symbol, address);
            }
        }
    }

    return address;
}

/* convert an RVA into a symbol */
const char* vmi_translate_v2sym(vmi_instance_t vmi, addr_t base_vaddr, vmi_pid_t pid, addr_t rva)
{
    char *ret = NULL;

    if (VMI_FAILURE == rva_cache_get(vmi, base_vaddr, pid, rva, &ret)) {
        if (vmi->os_interface && vmi->os_interface->os_rva2sym) {
            ret = vmi->os_interface->os_rva2sym(vmi, rva, base_vaddr, pid);
        }

        if (ret) {
            rva_cache_set(vmi, base_vaddr, pid, rva, ret);
        }
    }

    return ret;
}

/* finds the address of the page global directory for a given pid */
addr_t vmi_pid_to_dtb (vmi_instance_t vmi, vmi_pid_t pid)
{
    addr_t dtb = 0;

    if (VMI_FAILURE == pid_cache_get(vmi, pid, &dtb)) {
        if (vmi->os_interface && vmi->os_interface->os_pid_to_pgd) {
            dtb = vmi->os_interface->os_pid_to_pgd(vmi, pid);
        }

        if (dtb) {
            pid_cache_set(vmi, pid, dtb);
        }
    }

    return dtb;
}

/* finds the pid for a given dtb */
vmi_pid_t vmi_dtb_to_pid (vmi_instance_t vmi, addr_t dtb)
{
    vmi_pid_t pid = -1;

    if (vmi->os_interface && vmi->os_interface->os_pgd_to_pid) {
        pid = vmi->os_interface->os_pgd_to_pid(vmi, dtb);
    }

    return pid;
}

void *
vmi_read_page (vmi_instance_t vmi, addr_t frame_num)
{
    if (!frame_num) {
        return NULL ;
    }
    else {
        return driver_read_page(vmi, frame_num);
    }
}

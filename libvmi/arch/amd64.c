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
#include "amd64.h"
#include <glib.h>
#include <stdlib.h>
#include <sys/mman.h>

/* utility bit grabbing functions */
static inline
uint64_t get_bits_51to12 (uint64_t value)
{
    return value & 0x000FFFFFFFFFF000ULL;
}

/* PML4 Table  */
static inline
addr_t get_pml4_index (addr_t vaddr)
{
    return (vaddr & 0x0000FF8000000000ULL) >> 36;
}

static inline
uint64_t get_pml4e (vmi_instance_t vmi,
    addr_t vaddr,
    reg_t cr3,
    addr_t *pml4e_address)
{
    uint64_t value;
    *pml4e_address = get_bits_51to12(cr3) | get_pml4_index(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup pml4e_address = 0x%.16"PRIx64"\n", *pml4e_address);
    if(VMI_FAILURE == vmi_read_64_pa(vmi, *pml4e_address, &value)) {
        value = 0;
    }
    return value;
}

static inline
addr_t get_pdpt_index_ia32e (addr_t vaddr)
{
    return (vaddr & 0x0000007FC0000000ULL) >> 27;
}

static inline
uint64_t get_pdpte_ia32e (vmi_instance_t vmi,
    addr_t vaddr,
    uint64_t pml4e,
    addr_t *pdpte_address)
{
    uint64_t value;
    *pdpte_address = get_bits_51to12(pml4e) | get_pdpt_index_ia32e(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpte_address = 0x%.16"PRIx64"\n", *pdpte_address);
    if(VMI_FAILURE == vmi_read_64_pa(vmi, *pdpte_address, &value)) {
        value = 0;
    }
    return value;
}

static inline
uint64_t pdba_base_ia32e (uint64_t pdpe)
{
    return get_bits_51to12(pdpe);
}

static inline
uint64_t get_pd_index_ia32e (addr_t vaddr)
{
    return (vaddr & 0x000000003FE00000ULL) >> 18;
}

static inline
uint64_t get_pde_ia32e (vmi_instance_t vmi,
    addr_t vaddr,
    uint64_t pdpte,
    addr_t *pde_address)
{
    uint64_t value;
    *pde_address = get_bits_51to12(pdpte) | get_pd_index_ia32e(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pde_address = 0x%.16"PRIx64"\n", *pde_address);
    if(VMI_FAILURE == vmi_read_64_pa(vmi, *pde_address, &value)) {
        value = 0;
    }
    return value;
}

static inline
uint64_t get_pt_index_ia32e (addr_t vaddr)
{
    return (vaddr & 0x00000000001FF000ULL) >> 9;
}

static inline
uint64_t get_pte_ia32e (vmi_instance_t vmi,
    addr_t vaddr,
    uint64_t pde,
    addr_t *pte_address)
{
    uint64_t value;
    *pte_address = get_bits_51to12(pde) | get_pt_index_ia32e(vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_address = 0x%.16"PRIx64"\n", *pte_address);
    if(VMI_FAILURE == vmi_read_64_pa(vmi, *pte_address, &value)) {
        value = 0;
    }
    return value;
}

static inline
uint64_t pte_pfn_ia32e (uint64_t pte)
{
    return get_bits_51to12(pte);
}

static inline
uint64_t get_paddr_ia32e (addr_t vaddr, uint64_t pte)
{
    return get_bits_51to12(pte) | (vaddr & 0x0000000000000FFFULL);
}

static inline
uint64_t get_gigpage_ia32e (addr_t vaddr, uint64_t pdpte)
{
    return (pdpte & 0x000FFFFFC0000000ULL) | (vaddr & 0x000000003FFFFFFFULL);
}

static inline
uint64_t get_2megpage_ia32e (addr_t vaddr, uint64_t pde)
{
    return (pde & 0x000FFFFFFFE00000ULL) | (vaddr & 0x00000000001FFFFFULL);
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

    if (ENTRY_PRESENT(vmi->os_type, pml4e)) {
        info->l4_v = pml4e;

        pdpte = get_pdpte_ia32e(vmi, vaddr, pml4e, &info->l3_a);
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpte = 0x%.16"PRIx64"\n", pdpte);

        if (ENTRY_PRESENT(vmi->os_type, pdpte)) {
            info->l3_v = pdpte;
            if (PAGE_SIZE_FLAG(pdpte)) { // pdpte maps a 1GB page
                info->paddr = get_gigpage_ia32e(vaddr, pdpte);
                info->size = VMI_PS_1GB;
                dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 1GB page\n");
            }
            else {
                pde = get_pde_ia32e(vmi, vaddr, pdpte, &info->l2_a);
                dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pde = 0x%.16"PRIx64"\n", pde);
            }

            if (ENTRY_PRESENT(vmi->os_type, pde)) {
                info->l2_v = pde;
                if (PAGE_SIZE_FLAG(pde)) { // pde maps a 2MB page
                    info->paddr = get_2megpage_ia32e(vaddr, pde);
                    info->size = VMI_PS_2MB;
                    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 2MB page\n");
                }
                else {
                    pte = get_pte_ia32e(vmi, vaddr, pde, &info->l1_a);
                    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte = 0x%.16"PRIx64"\n", pte);
                }

                if (ENTRY_PRESENT(vmi->os_type, pte)) {
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

            if(PAGE_SIZE_FLAG(pdpte_value)) {
                page_info_t *p = g_malloc0(sizeof(page_info_t));
                p->vaddr = vaddr;
                p->paddr = get_gigpage_ia32e(vaddr, pdpte_value);
                p->size = VMI_PS_1GB;
                p->l4_a = pml4e_a;
                p->l4_v = pml4e_value;
                p->l3_a = pdpte_a;
                p->l3_v = pdpte_value;
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

                if(ENTRY_PRESENT(vmi->os_type, entry)) {

                    if(PAGE_SIZE_FLAG(entry)) {
                        page_info_t *p = g_malloc0(sizeof(page_info_t));
                        p->vaddr = soffset;
                        p->paddr = get_2megpage_ia32e(vaddr, entry);
                        p->size = VMI_PS_2MB;
                        p->l4_a = pml4e_a;
                        p->l4_v = pml4e_value;
                        p->l3_a = pdpte_a;
                        p->l3_v = pdpte_value;
                        p->l2_a = pgd_curr;
                        p->l2_v = entry;
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

                        if(ENTRY_PRESENT(vmi->os_type, pte_entry)) {
                            page_info_t *p = g_malloc0(sizeof(page_info_t));
                            p->vaddr = soffset + k * VMI_PS_4KB;
                            p->paddr = get_paddr_ia32e(vaddr, pte_entry);
                            p->size = VMI_PS_4KB;
                            p->l4_a = pml4e_a;
                            p->l4_v = pml4e_value;
                            p->l3_a = pdpte_a;
                            p->l3_v = pdpte_value;
                            p->l2_a = pgd_curr;
                            p->l2_v = entry;
                            p->l1_a = pte_curr;
                            p->l1_v = pte_entry;
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

status_t amd64_init(vmi_instance_t vmi) {

    if(!vmi->arch_interface) {
        vmi->arch_interface = safe_malloc(sizeof(struct arch_interface));
        bzero(vmi->arch_interface, sizeof(struct arch_interface));
    }

    vmi->arch_interface->v2p = v2p_ia32e;
    vmi->arch_interface->get_va_pages = get_va_pages_ia32e;

    return VMI_SUCCESS;
}

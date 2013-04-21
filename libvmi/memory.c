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

uint64_t get_pml4e (vmi_instance_t vmi, addr_t vaddr, reg_t cr3)
{
    uint64_t value = 0;
    addr_t pml4e_address = get_bits_51to12(cr3) | get_pml4_index(vaddr);

    dbprint("--PTLookup pml4e_address = 0x%.16"PRIx64"\n", pml4e_address);
    vmi_read_64_pa(vmi, pml4e_address, &value);
    return value;
}

/* page directory pointer table */
uint32_t get_pdptb (uint32_t pdpr)
{
    return pdpr & 0xFFFFFFE0;
}

uint32_t pdpi_index (uint32_t pdpi)
{
    return (pdpi >> 30) * sizeof(uint64_t);
}

uint64_t get_pdpi (vmi_instance_t instance, uint32_t vaddr, uint32_t cr3)
{
    uint64_t value;
    uint32_t pdpi_entry = get_pdptb(cr3) + pdpi_index(vaddr);

    dbprint("--PTLookup: pdpi_entry = 0x%.8x\n", pdpi_entry);
    vmi_read_64_pa(instance, pdpi_entry, &value);
    return value;
}

addr_t get_pdpt_index_ia32e (addr_t vaddr)
{
    return (vaddr & 0x0000007FC0000000ULL) >> 27;
}

uint64_t get_pdpte_ia32e (vmi_instance_t vmi, addr_t vaddr, uint64_t pml4e)
{
    uint64_t value = 0;
    addr_t pdpte_address = get_bits_51to12(pml4e) | get_pdpt_index_ia32e(vaddr);
    dbprint("--PTLookup: pdpte_address = 0x%.16"PRIx64"\n", pdpte_address);
    vmi_read_64_pa(vmi, pdpte_address, &value);
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

uint32_t get_pgd_nopae (vmi_instance_t instance, uint32_t vaddr, uint32_t pdpe)
{
    uint32_t value;
    uint32_t pgd_entry = pdba_base_nopae(pdpe) + pgd_index(instance, vaddr);
    dbprint("--PTLookup: pgd_entry = 0x%.8x\n", pgd_entry);
    vmi_read_32_pa(instance, pgd_entry, &value);
    return value;
}

uint64_t get_pgd_pae (vmi_instance_t instance, uint32_t vaddr, uint64_t pdpe)
{
    uint64_t value;
    uint32_t pgd_entry = pdba_base_pae(pdpe) + pgd_index(instance, vaddr);
    dbprint("--PTLookup: pgd_entry = 0x%.8x\n", pgd_entry);
    vmi_read_64_pa(instance, pgd_entry, &value);
    return value;
}

uint64_t get_pd_index_ia32e (addr_t vaddr)
{
    return (vaddr & 0x000000003FE00000ULL) >> 18;
}

uint64_t get_pde_ia32e (vmi_instance_t vmi, addr_t vaddr, uint64_t pdpte)
{
    uint64_t value = 0;
    addr_t pde_address = get_bits_51to12(pdpte) | get_pd_index_ia32e(vaddr);
    dbprint("--PTLookup: pde_address = 0x%.16"PRIx64"\n", pde_address);
    vmi_read_64_pa(vmi, pde_address, &value);
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

uint32_t get_pte_nopae (vmi_instance_t instance, uint32_t vaddr, uint32_t pgd)
{
    uint32_t value;
    uint32_t pte_entry = ptba_base_nopae(pgd) + pte_index(instance, vaddr);
    dbprint("--PTLookup: pte_entry = 0x%.8x\n", pte_entry);
    vmi_read_32_pa(instance, pte_entry, &value);
    return value;
}

uint64_t get_pte_pae (vmi_instance_t instance, uint32_t vaddr, uint64_t pgd)
{
    uint64_t value;
    uint32_t pte_entry = ptba_base_pae(pgd) + pte_index(instance, vaddr);
    dbprint("--PTLookup: pte_entry = 0x%.8x\n", pte_entry);
    vmi_read_64_pa(instance, pte_entry, &value);
    return value;
}

uint64_t get_pt_index_ia32e (addr_t vaddr)
{
    return (vaddr & 0x00000000001FF000ULL) >> 9;
}

uint64_t get_pte_ia32e (vmi_instance_t vmi, addr_t vaddr, uint64_t pde)
{
    uint64_t value = 0;
    addr_t pte_address = get_bits_51to12(pde) | get_pt_index_ia32e(vaddr);
    dbprint("--PTLookup: pte_address = 0x%.16"PRIx64"\n", pte_address);
    vmi_read_64_pa(vmi, pte_address, &value);
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
            dbprint("--Buffalo: page file = %d, frame = 0x%.8x\n",
                    pfnum, pfframe);
        }
        /* demand zero */
        else if (pfnum == 0 && pfframe == 0) {
            dbprint("--Buffalo: demand zero page\n");
        }
    }

    else if (get_transition_bit(entry) && !get_prototype_bit(entry)) {
        /* transition */
        dbprint("--Buffalo: page in transition\n");
    }

    else if (!pde && get_prototype_bit(entry)) {
        /* prototype */
        dbprint("--Buffalo: prototype entry\n");
    }

    else if (entry == 0) {
        /* zero */
        dbprint("--Buffalo: entry is zero\n");
    }

    else {
        /* zero */
        dbprint("--Buffalo: unknown\n");
    }
}

/* translation */
addr_t v2p_nopae (vmi_instance_t vmi, addr_t dtb, addr_t vaddr)
{
    addr_t paddr = 0;
    uint32_t pgd, pte;

    dbprint("--PTLookup: lookup vaddr = 0x%.16"PRIx64"\n", vaddr);
    dbprint("--PTLookup: dtb = 0x%.16"PRIx64"\n", dtb);
    pgd = get_pgd_nopae(vmi, vaddr, dtb);
    dbprint("--PTLookup: pgd = 0x%.8"PRIx32"\n", pgd);

    if (entry_present(vmi->os_type, pgd)) {
        if (page_size_flag(pgd)) {
            paddr = get_large_paddr(vmi, vaddr, pgd);
            dbprint("--PTLookup: 4MB page 0x%"PRIx32"\n", pgd);
        }
        else {
            pte = get_pte_nopae(vmi, vaddr, pgd);
            dbprint("--PTLookup: pte = 0x%.8"PRIx32"\n", pte);
            if (entry_present(vmi->os_type, pte)) {
                paddr = get_paddr_nopae(vaddr, pte);
            }
            else {
                buffalo_nopae(vmi, pte, 1);
            }
        }
    }
    else {
        buffalo_nopae(vmi, pgd, 0);
    }
    dbprint("--PTLookup: paddr = 0x%.16"PRIx64"\n", paddr);
    return paddr;
}

addr_t v2p_pae (vmi_instance_t vmi, addr_t dtb, addr_t vaddr)
{
    addr_t paddr = 0;
    uint64_t pdpe, pgd, pte;

    dbprint("--PTLookup: lookup vaddr = 0x%.16"PRIx64"\n", vaddr);
    dbprint("--PTLookup: dtb = 0x%.16"PRIx64"\n", dtb);
    pdpe = get_pdpi(vmi, vaddr, dtb);
    dbprint("--PTLookup: pdpe = 0x%.16"PRIx64"\n", pdpe);
    if (!entry_present(vmi->os_type, pdpe)) {
        return paddr;
    }
    pgd = get_pgd_pae(vmi, vaddr, pdpe);
    dbprint("--PTLookup: pgd = 0x%.16"PRIx64"\n", pgd);

    if (entry_present(vmi->os_type, pgd)) {
        if (page_size_flag(pgd)) {
            paddr = get_large_paddr(vmi, vaddr, pgd);
            dbprint("--PTLookup: 2MB page\n");
        }
        else {
            pte = get_pte_pae(vmi, vaddr, pgd);
            dbprint("--PTLookup: pte = 0x%.16"PRIx64"\n", pte);
            if (entry_present(vmi->os_type, pte)) {
                paddr = get_paddr_pae(vaddr, pte);
            }
        }
    }
    dbprint("--PTLookup: paddr = 0x%.16"PRIx64"\n", paddr);
    return paddr;
}

addr_t v2p_ia32e (vmi_instance_t vmi, addr_t dtb, addr_t vaddr)
{
    addr_t paddr = 0;
    uint64_t pml4e = 0, pdpte = 0, pde = 0, pte = 0;

    // are we in compatibility mode OR 64-bit mode ???

    // validate address based on above (e.g., is it canonical?)

    // determine what MAXPHYADDR is

    dbprint("--PTLookup: lookup vaddr = 0x%.16"PRIx64"\n", vaddr);
    dbprint("--PTLookup: dtb = 0x%.16"PRIx64"\n", dtb);
    pml4e = get_pml4e(vmi, vaddr, dtb);
    dbprint("--PTLookup: pml4e = 0x%.16"PRIx64"\n", pml4e);

    if (entry_present(vmi->os_type, pml4e)) {
        pdpte = get_pdpte_ia32e(vmi, vaddr, pml4e);
        dbprint("--PTLookup: pdpte = 0x%.16"PRIx64"\n", pdpte);

        if (entry_present(vmi->os_type, pdpte)) {
            if (page_size_flag(pdpte)) { // pdpte maps a 1GB page
                paddr = get_gigpage_ia32e(vaddr, pdpte);
                dbprint("--PTLookup: 1GB page\n");
            }
            else {
                pde = get_pde_ia32e(vmi, vaddr, pdpte);
                dbprint("--PTLookup: pde = 0x%.16"PRIx64"\n", pde);
            }

            if (entry_present(vmi->os_type, pde)) {
                if (page_size_flag(pde)) { // pde maps a 2MB page
                    paddr = get_2megpage_ia32e(vaddr, pde);
                    dbprint("--PTLookup: 2MB page\n");
                }
                else {
                    pte = get_pte_ia32e(vmi, vaddr, pde);
                    dbprint("--PTLookup: pte = 0x%.16"PRIx64"\n", pte);
                }

                if (entry_present(vmi->os_type, pte)) {
                    paddr = get_paddr_ia32e(vaddr, pte);
                }
            }
        }
    }

    dbprint("--PTLookup: paddr = 0x%.16"PRIx64"\n", paddr);
    return paddr;
}

addr_t vmi_pagetable_lookup (vmi_instance_t vmi, addr_t dtb, addr_t vaddr)
{
    addr_t paddr = 0;

    /* check if entry exists in the cachec */
    if (VMI_SUCCESS == v2p_cache_get(vmi, vaddr, dtb, &paddr)) {

        /* verify that address is still valid */
        uint8_t value = 0;

        if (VMI_SUCCESS == vmi_read_8_pa(vmi, paddr, &value)) {
            return paddr;
        }
        else {
            v2p_cache_del(vmi, vaddr, dtb);
        }
    }

    /* do the actual page walk in guest memory */
    if (vmi->page_mode == VMI_PM_LEGACY) {
        paddr = v2p_nopae(vmi, dtb, vaddr);
    }
    else if (vmi->page_mode == VMI_PM_PAE) {
        paddr = v2p_pae(vmi, dtb, vaddr);
    }
    else if (vmi->page_mode == VMI_PM_IA32E) {
        paddr = v2p_ia32e(vmi, dtb, vaddr);
    }
    else {
        errprint("Invalid paging mode during vmi_pagetable_lookup\n");
    }

    /* add this to the cache */
    if (paddr) {
        v2p_cache_set(vmi, vaddr, dtb, paddr);
    }
    return paddr;
}

/* expose virtual to physical mapping for kernel space via api call */
addr_t vmi_translate_kv2p (vmi_instance_t vmi, addr_t virt_address)
{
    reg_t cr3 = 0;

    if (vmi->kpgd) {
        cr3 = vmi->kpgd;
    }
    else {
        driver_get_vcpureg(vmi, &cr3, CR3, 0);
    }
    if (!cr3) {
        dbprint("--early bail on v2p lookup because cr3 is zero\n");
        return 0;
    }
    else {
        return vmi_pagetable_lookup(vmi, cr3, virt_address);
    }
}

/* expose virtual to physical mapping for user space via api call */
addr_t vmi_translate_uv2p_nocache (vmi_instance_t vmi, addr_t virt_address,
        int pid)
{
    addr_t dtb = vmi_pid_to_dtb(vmi, pid);

    if (!dtb) {
        dbprint("--early bail on v2p lookup because dtb is zero\n");
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

addr_t vmi_translate_uv2p (vmi_instance_t vmi, addr_t virt_address, int pid)
{
    addr_t dtb = vmi_pid_to_dtb(vmi, pid);

    if (!dtb) {
        dbprint("--early bail on v2p lookup because dtb is zero\n");
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
addr_t vmi_translate_ksym2v (vmi_instance_t vmi, char *symbol)
{
    addr_t ret = 0;

    addr_t base_vaddr = 0;
    if (VMI_OS_WINDOWS == vmi->os_type) {
        base_vaddr = vmi->os.windows_instance.ntoskrnl_va;
    }

    if (VMI_FAILURE == sym_cache_get(vmi, base_vaddr, 0, symbol, &ret)) {
        if (VMI_OS_LINUX == vmi->os_type) {
            if (VMI_FAILURE
                    == linux_system_map_symbol_to_address(vmi, symbol, &ret)) {
                ret = 0;
            }
        }
        else if (VMI_OS_WINDOWS == vmi->os_type) {
            if (VMI_FAILURE == windows_symbol_to_address(vmi, symbol, &ret)) {
                ret = 0;
            }
        }

        if (ret) {
            sym_cache_set(vmi, base_vaddr, 0, symbol, ret);
        }
    }

    return ret;
}

/* convert a symbol into an address */
addr_t vmi_translate_sym2v (vmi_instance_t vmi, addr_t base_vaddr, uint32_t pid, char *symbol)
{
    addr_t ret = 0;

    if (VMI_FAILURE == sym_cache_get(vmi, base_vaddr, pid, symbol, &ret)) {

        if (VMI_OS_LINUX == vmi->os_type) {
            // TODO
            return VMI_FAILURE;
        }
        else if (VMI_OS_WINDOWS == vmi->os_type) {
            if (VMI_FAILURE == windows_export_to_rva(vmi, symbol, base_vaddr, pid, &ret)) {
                ret = 0;
            } else {
                ret += base_vaddr;
            }
        }

        if (ret) {
            sym_cache_set(vmi, base_vaddr, pid, symbol, ret);
        }
    }

    return ret;
}
/* convert an RVA into a symbol */
const char* vmi_translate_v2sym(vmi_instance_t vmi, addr_t base_vaddr, uint32_t pid, addr_t rva)
{
    char *ret = NULL;

    if (VMI_FAILURE == rva_cache_get(vmi, base_vaddr, pid, rva, &ret)) {

        if (VMI_OS_LINUX == vmi->os_type) {
            // TODO
            return ret;
        }
        else if (VMI_OS_WINDOWS == vmi->os_type) {
            windows_rva_to_export(vmi, rva, base_vaddr, pid, &ret);
        }

        if (ret) {
            rva_cache_set(vmi, base_vaddr, pid, rva, ret);
        }
    }

    return ret;
}

/* finds the address of the page global directory for a given pid */
addr_t vmi_pid_to_dtb (vmi_instance_t vmi, int pid)
{
    addr_t dtb = 0;

    if (VMI_FAILURE == pid_cache_get(vmi, pid, &dtb)) {
        if (VMI_OS_LINUX == vmi->os_type) {
            dtb = linux_pid_to_pgd(vmi, pid);
        }
        else if (VMI_OS_WINDOWS == vmi->os_type) {
            dtb = windows_pid_to_pgd(vmi, pid);
        }

        if (dtb) {
            pid_cache_set(vmi, pid, dtb);
        }
    }

    return dtb;
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

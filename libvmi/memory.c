/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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
int entry_present (unsigned long entry){
    return vmi_get_bit(entry, 0);
}

int page_size_flag (unsigned long entry){
    return vmi_get_bit(entry, 7);
}

/* page directory pointer table */
uint32_t get_pdptb (uint32_t pdpr){
    return pdpr & 0xFFFFFFE0;
}

uint32_t pdpi_index (uint32_t pdpi){
    return (pdpi >> 30) * sizeof(uint64_t);
}

uint64_t get_pdpi (vmi_instance_t instance, uint32_t vaddr, uint32_t cr3)
{
    uint64_t value;
    uint32_t pdpi_entry = get_pdptb(cr3) + pdpi_index(vaddr);
    dbprint("--PTLookup: pdpi_entry = 0x%.8x\n", pdpi_entry);
    vmi_read_64_ma(instance, pdpi_entry, &value);
    return value;
}

/* page directory */
uint32_t pgd_index (vmi_instance_t instance, uint32_t address){
    if (!instance->pae){
        return (((address) >> 22) & 0x3FF) * sizeof(uint32_t);
    }
    else{
        return (((address) >> 21) & 0x1FF) * sizeof(uint64_t);
    }
}

uint32_t pdba_base_nopae (uint32_t pdpe){
    return pdpe & 0xFFFFF000;
}

uint64_t pdba_base_pae (uint64_t pdpe){
    return pdpe & 0xFFFFFF000ULL;
}

uint32_t get_pgd_nopae (vmi_instance_t instance, uint32_t vaddr, uint32_t pdpe)
{
    uint32_t value;
    uint32_t pgd_entry = pdba_base_nopae(pdpe) + pgd_index(instance, vaddr);
    dbprint("--PTLookup: pgd_entry = 0x%.8x\n", pgd_entry);
    vmi_read_32_ma(instance, pgd_entry, &value);
    return value;
}

uint64_t get_pgd_pae (vmi_instance_t instance, uint32_t vaddr, uint64_t pdpe)
{
    uint64_t value;
    uint32_t pgd_entry = pdba_base_pae(pdpe) + pgd_index(instance, vaddr);
    dbprint("--PTLookup: pgd_entry = 0x%.8x\n", pgd_entry);
    vmi_read_64_ma(instance, pgd_entry, &value);
    return value;
}

/* page table */
uint32_t pte_index (vmi_instance_t instance, uint32_t address){
    if (!instance->pae){
        return (((address) >> 12) & 0x3FF) * sizeof(uint32_t);
    }
    else{
        return (((address) >> 12) & 0x1FF) * sizeof(uint64_t); 
    }
}
        
uint32_t ptba_base_nopae (uint32_t pde){
    return pde & 0xFFFFF000;
}

uint64_t ptba_base_pae (uint64_t pde){
    return pde & 0xFFFFFF000ULL;
}

uint32_t get_pte_nopae (vmi_instance_t instance, uint32_t vaddr, uint32_t pgd){
    uint32_t value;
    uint32_t pte_entry = ptba_base_nopae(pgd) + pte_index(instance, vaddr);
    dbprint("--PTLookup: pte_entry = 0x%.8x\n", pte_entry);
    vmi_read_32_ma(instance, pte_entry, &value);
    return value;
}

uint64_t get_pte_pae (vmi_instance_t instance, uint32_t vaddr, uint64_t pgd){
    uint64_t value;
    uint32_t pte_entry = ptba_base_pae(pgd) + pte_index(instance, vaddr);
    dbprint("--PTLookup: pte_entry = 0x%.8x\n", pte_entry);
    vmi_read_64_ma(instance, pte_entry, &value);
    return value;
}

/* page */
uint32_t pte_pfn_nopae (uint32_t pte){
    return pte & 0xFFFFF000;
}

uint64_t pte_pfn_pae (uint64_t pte){
    return pte & 0xFFFFFF000ULL;
}

uint32_t get_paddr_nopae (uint32_t vaddr, uint32_t pte){
    return pte_pfn_nopae(pte) | (vaddr & 0xFFF);
}

uint64_t get_paddr_pae (uint32_t vaddr, uint64_t pte){
    return pte_pfn_pae(pte) | (vaddr & 0xFFF);
}

uint32_t get_large_paddr (
        vmi_instance_t instance, uint32_t vaddr, uint32_t pgd_entry)
{
    if (!instance->pae){
        return (pgd_entry & 0xFFC00000) | (vaddr & 0x3FFFFF);
    }
    else{
        return (pgd_entry & 0xFFE00000) | (vaddr & 0x1FFFFF);
    }
}

/* "buffalo" routines
 * see "Using Every Part of the Buffalo in Windows Memory Analysis" by
 * Jesse D. Kornblum for details. 
 * for now, just test the bits and print out details */
int get_transition_bit(uint32_t entry)
{
    return vmi_get_bit(entry, 11);
}

int get_prototype_bit(uint32_t entry)
{
    return vmi_get_bit(entry, 10);
}

void buffalo_nopae (vmi_instance_t instance, uint32_t entry, int pde)
{
    /* similar techniques are surely doable in linux, but for now
     * this is only testing for windows domains */
    if (!instance->os_type == VMI_OS_WINDOWS){
        return;
    }

    if (!get_transition_bit(entry) && !get_prototype_bit(entry)){
        uint32_t pfnum = (entry >> 1) & 0xF;
        uint32_t pfframe = entry & 0xFFFFF000;

        /* pagefile */
        if (pfnum != 0 && pfframe != 0){
            dbprint("--Buffalo: page file = %d, frame = 0x%.8x\n",
                pfnum, pfframe);
        }
        /* demand zero */
        else if (pfnum == 0 && pfframe == 0){
            dbprint("--Buffalo: demand zero page\n");
        }
    }

    else if (get_transition_bit(entry) && !get_prototype_bit(entry)){
        /* transition */
        dbprint("--Buffalo: page in transition\n");
    }

    else if (!pde && get_prototype_bit(entry)){
        /* prototype */
        dbprint("--Buffalo: prototype entry\n");
    }

    else if (entry == 0){
        /* zero */
        dbprint("--Buffalo: entry is zero\n");
    }

    else{
        /* zero */
        dbprint("--Buffalo: unknown\n");
    }
}

/* translation */
uint32_t v2p_nopae(vmi_instance_t vmi, addr_t dtb, uint32_t vaddr)
{
    uint32_t paddr = 0;
    uint32_t pgd, pte;
        
    dbprint("--PTLookup: lookup vaddr = 0x%.8x\n", vaddr);
    dbprint("--PTLookup: dtb = 0x%.8x\n", dtb);
    pgd = get_pgd_nopae(vmi, vaddr, dtb);
    dbprint("--PTLookup: pgd = 0x%.8x\n", pgd);
        
    if (entry_present(pgd)){
        if (page_size_flag(pgd)){
            paddr = get_large_paddr(vmi, vaddr, pgd);
            dbprint("--PTLookup: 4MB page\n", pgd);
        }
        else{
            pte = get_pte_nopae(vmi, vaddr, pgd);
            dbprint("--PTLookup: pte = 0x%.8x\n", pte);
            if (entry_present(pte)){
                paddr = get_paddr_nopae(vaddr, pte);
            }
            else{
                buffalo_nopae(vmi, pte, 1);
            }
        }
    }
    else{
        buffalo_nopae(vmi, pgd, 0);
    }
    dbprint("--PTLookup: paddr = 0x%.8x\n", paddr);
    return paddr;
}

uint32_t v2p_pae (vmi_instance_t vmi, addr_t dtb, uint32_t vaddr)
{
    uint32_t paddr = 0;
    uint64_t pdpe, pgd, pte;
        
    dbprint("--PTLookup: lookup vaddr = 0x%.8x\n", vaddr);
    dbprint("--PTLookup: dtb = 0x%.8x\n", dtb);
    pdpe = get_pdpi(vmi, vaddr, dtb);
    dbprint("--PTLookup: pdpe = 0x%.16x\n", pdpe);
    if (!entry_present(pdpe)){
        return paddr;
    }
    pgd = get_pgd_pae(vmi, vaddr, pdpe);
    dbprint("--PTLookup: pgd = 0x%.16x\n", pgd);

    if (entry_present(pgd)){
        if (page_size_flag(pgd)){
            paddr = get_large_paddr(vmi, vaddr, pgd);
            dbprint("--PTLookup: 2MB page\n");
        }
        else{
            pte = get_pte_pae(vmi, vaddr, pgd);
            dbprint("--PTLookup: pte = 0x%.16x\n", pte);
            if (entry_present(pte)){
                paddr = get_paddr_pae(vaddr, pte);
            }
        }
    }
    dbprint("--PTLookup: paddr = 0x%.8x\n", paddr);
    return paddr;
}

addr_t vmi_pagetable_lookup (vmi_instance_t vmi, addr_t dtb, uint32_t vaddr)
{
    addr_t paddr = 0;

    /* check if entry exists in the cachec */
    if (VMI_SUCCESS == v2p_cache_get(vmi, vaddr, dtb, &paddr)){

        /* verify that address is still valid */
        uint8_t value = 0;
        if (VMI_SUCCESS == vmi_read_8_pa(vmi, paddr, &value)){
            return paddr;
        }
        else{
            v2p_cache_del(vmi, vaddr, dtb);
        }
    }

    /* do the actual page walk in guest memory */
    if (vmi->pae){
        paddr = v2p_pae(vmi, dtb, vaddr);
    }
    else{
        paddr = v2p_nopae(vmi, dtb, vaddr);
    }

    /* add this to the cache */
    if (paddr){
        v2p_cache_set(vmi, vaddr, dtb, paddr);
    }
    return paddr;
}

/* expose virtual to physical mapping for kernel space via api call */
addr_t vmi_translate_kv2p(vmi_instance_t vmi, addr_t virt_address)
{
    reg_t cr3 = 0;
    driver_get_vcpureg(vmi, &cr3, CR3, 0);
    if (!cr3){
        dbprint("--early bail on v2p lookup because cr3 is zero\n");
        return 0;
    }
    else{
        return vmi_pagetable_lookup(vmi, cr3, virt_address);
    }
}

/* expose virtual to physical mapping for user space via api call */
addr_t vmi_translate_uv2p_nocache(vmi_instance_t vmi, addr_t virt_address, int pid)
{
    addr_t dtb = vmi_pid_to_dtb(vmi, pid);
    if (!dtb){
        dbprint("--early bail on v2p lookup because dtb is zero\n");
        return 0;
    }
    else{
        addr_t rtnval = vmi_pagetable_lookup(vmi, dtb, virt_address);
        if (!rtnval){
            pid_cache_del(vmi, pid);
        }
        return rtnval;    
    }
}

addr_t vmi_translate_uv2p(vmi_instance_t vmi, addr_t virt_address, int pid)
{
    addr_t dtb = vmi_pid_to_dtb(vmi, pid);
    if (!dtb){
        dbprint("--early bail on v2p lookup because dtb is zero\n");
        return 0;
    }
    else{
        addr_t rtnval = vmi_pagetable_lookup(vmi, dtb, virt_address);
        if (!rtnval){
            if (VMI_SUCCESS == pid_cache_del(vmi, pid)){
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

    if (VMI_FAILURE == sym_cache_get(vmi, symbol, &ret)){
        if (VMI_OS_LINUX == vmi->os_type){
            if (VMI_FAILURE == linux_system_map_symbol_to_address(vmi, symbol, &ret)){
                ret = 0;
            }
        }
        else if (VMI_OS_WINDOWS == vmi->os_type){
            if (VMI_FAILURE == windows_symbol_to_address(vmi, symbol, &ret)){
                ret = 0;
            }
        }

        if (ret){
            sym_cache_set(vmi, symbol, ret);
        }
    }

    return ret;
}

/* finds the address of the page global directory for a given pid */
addr_t vmi_pid_to_dtb (vmi_instance_t vmi, int pid)
{
    addr_t dtb = 0;

    if (VMI_FAILURE == pid_cache_get(vmi, pid, &dtb)){
        if (VMI_OS_LINUX == vmi->os_type){
            dtb = linux_pid_to_pgd(vmi, pid);
        }
        else if (VMI_OS_WINDOWS == vmi->os_type){
            dtb = windows_pid_to_pgd(vmi, pid);
        }

        if (dtb){
            pid_cache_set(vmi, pid, dtb);
        }
    }

    return dtb;
}

void *vmi_read_page (vmi_instance_t vmi, unsigned long frame_num, int is_pfn)
{
    unsigned long mfn;
    if (is_pfn){
        mfn = driver_pfn_to_mfn(vmi, frame_num);
    }
    else{
        mfn = frame_num;
    }

    if (!mfn){
        return NULL;
    }
    else{
        return driver_read_page(vmi, mfn);
    }
}

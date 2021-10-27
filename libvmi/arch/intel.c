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

#include <glib.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "private.h"
#include "x86.h"
#include "driver/driver_wrapper.h"
#include "arch/intel.h"

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
status_t get_pdpi (vmi_instance_t instance,
                   access_context_t *ctx,
                   page_info_t *info)
{
    ctx->addr = get_pdptb(info->pt) + pdpi_index(info->vaddr);

    if (VMI_FAILURE == vmi_read_64(instance, ctx, &info->x86_pae.pdpe_value)) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: failed to read pdpi_location = 0x%.16"PRIx64"\n", ctx->addr);
        return VMI_FAILURE;
    }

    info->x86_pae.pdpe_location = ctx->addr;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpe_location = 0x%.16"PRIx64"\n",
            info->x86_pae.pdpe_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpe_value = 0x%.16"PRIx64"\n",
            info->x86_pae.pdpe_value);

    return VMI_SUCCESS;
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
status_t get_pgd_nopae (vmi_instance_t instance,
                        access_context_t *ctx,
                        page_info_t *info)
{
    ctx->addr = pdba_base_nopae(ctx->pt) + pgd_index_nopae(info->vaddr);
    info->x86_legacy.pgd_value = 0;

    if (VMI_FAILURE == vmi_read_32(instance, ctx, (uint32_t*)&info->x86_legacy.pgd_value)) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: failed to read pgd_location at = 0x%.8"PRIx64"\n", ctx->addr);
        return VMI_FAILURE;
    }

    info->x86_legacy.pgd_location = ctx->addr;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd_entry = 0x%.8"PRIx64"\n", info->x86_legacy.pgd_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd_entry = 0x%.8"PRIx64"\n", info->x86_legacy.pgd_value);
    return VMI_SUCCESS;
}

static inline
status_t get_pgd_pae (vmi_instance_t instance,
                      access_context_t *ctx,
                      page_info_t *info)
{
    ctx->addr = pdba_base_pae(info->x86_pae.pdpe_value) + pgd_index_pae(info->vaddr);

    if (VMI_FAILURE == vmi_read_64(instance, ctx, &info->x86_pae.pgd_value)) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: failed to read pgd_entry = 0x%.8"PRIx64"\n", ctx->addr);
        return VMI_FAILURE;
    }

    info->x86_pae.pgd_location = ctx->addr;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd_location = 0x%.8"PRIx64"\n", info->x86_pae.pgd_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd_value = 0x%.8"PRIx64"\n", info->x86_pae.pgd_value);
    return VMI_SUCCESS;
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
status_t get_pte_nopae (vmi_instance_t instance,
                        access_context_t *ctx,
                        page_info_t *info)
{
    ctx->addr = ptba_base_nopae(info->x86_legacy.pgd_value) + pte_index_nopae(info->vaddr);
    info->x86_legacy.pte_value = 0;

    if (VMI_FAILURE == vmi_read_32(instance, ctx, (uint32_t*)&info->x86_legacy.pte_value)) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: failed to read pte_entry = 0x%.8"PRIx64"\n", ctx->addr);
        return VMI_FAILURE;
    }

    info->x86_legacy.pte_location = ctx->addr;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_location = 0x%.8"PRIx64"\n", info->x86_legacy.pte_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_value = 0x%.8"PRIx64"\n", info->x86_legacy.pte_value);
    return VMI_SUCCESS;
}

static inline
status_t get_pte_pae (vmi_instance_t instance,
                      access_context_t *ctx,
                      page_info_t *info)
{
    ctx->addr = ptba_base_pae(info->x86_pae.pgd_value) + pte_index_pae(info->vaddr);

    if (VMI_FAILURE == vmi_read_64(instance, ctx, &info->x86_pae.pte_value)) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: failed to read pte_entry = 0x%.8"PRIx64"\n", ctx->addr);
        return VMI_FAILURE;
    }

    info->x86_pae.pte_location = ctx->addr;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_location = 0x%.8"PRIx64"\n", info->x86_pae.pte_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_value = 0x%.8"PRIx64"\n", info->x86_pae.pte_value);
    return VMI_SUCCESS;
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
    if (instance->os_type != VMI_OS_WINDOWS) {
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
status_t v2p_nopae (vmi_instance_t vmi,
                    addr_t npt,
                    page_mode_t npm,
                    addr_t pt,
                    addr_t vaddr,
                    page_info_t *info)
{
    status_t status;
    ACCESS_CONTEXT(ctx,
                   .npt = npt,
                   .npm = npm);

    info->npt = npt;
    info->npm = npm;
    info->pt = pt;
    info->pm = VMI_PM_LEGACY;
    info->vaddr = vaddr;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: lookup vaddr = 0x%.16"PRIx64", pt = 0x%.16"PRIx64"\n", vaddr, pt);
    status = get_pgd_nopae(vmi, &ctx, info);
    if (status != VMI_SUCCESS) {
        goto done;
    }

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pgd = 0x%.8"PRIx64"\n", info->x86_legacy.pgd_value);

    if (!ENTRY_PRESENT(vmi->x86.transition_pages, info->x86_legacy.pgd_value)) {
        buffalo_nopae(vmi, info->x86_legacy.pgd_value, 0);
        status = VMI_FAILURE;
        goto done;
    }

    if (PAGE_SIZE(info->x86_legacy.pgd_value) && (VMI_FILE == vmi->mode || vmi->x86.pse)) {
        info->paddr = get_large_paddr_nopae(vaddr, info->x86_legacy.pgd_value);
        info->size = VMI_PS_4MB;
        status = VMI_SUCCESS;
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 4MB page 0x%"PRIx64"\n", info->x86_legacy.pgd_value);
        goto done;
    }

    status = get_pte_nopae(vmi, &ctx, info);
    if (status != VMI_SUCCESS) {
        goto done;
    }

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte = 0x%.8"PRIx64"\n", info->x86_legacy.pte_value);

    if (!ENTRY_PRESENT(vmi->x86.transition_pages, info->x86_legacy.pte_value)) {
        buffalo_nopae(vmi, info->x86_legacy.pte_value, 1);
        status = VMI_FAILURE;
        goto done;
    }

    info->size = VMI_PS_4KB;
    info->paddr = get_paddr_nopae(vaddr, info->x86_legacy.pte_value);
    status = VMI_SUCCESS;

done:
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: paddr = 0x%.16"PRIx64"\n", info->paddr);

    if (valid_npm(npm)) {
        if ( VMI_FAILURE == vmi_nested_pagetable_lookup(vmi, 0, 0, npt, npm, info->paddr, &info->naddr, NULL) )
            return VMI_FAILURE;

        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: naddr = 0x%.16"PRIx64"\n", info->naddr);
    }

    return status;
}

status_t v2p_pae (vmi_instance_t vmi,
                  addr_t npt,
                  page_mode_t npm,
                  addr_t pt,
                  addr_t vaddr,
                  page_info_t *info)
{
    status_t status;
    ACCESS_CONTEXT(ctx,
                   .npt = npt,
                   .npm = npm);

    info->vaddr = vaddr;
    info->pm = VMI_PM_PAE;
    info->pt = pt,
          info->npt = npt;
    info->npm = npm;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: lookup vaddr = 0x%.16"PRIx64" dtb = 0x%.16"PRIx64"\n", vaddr, pt);
    status = get_pdpi(vmi, &ctx, info);

    if (status != VMI_SUCCESS) {
        goto done;
    }

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpe = 0x%"PRIx64"\n", info->x86_pae.pdpe_value);

    if (!ENTRY_PRESENT(vmi->x86.transition_pages, info->x86_pae.pdpe_value)) {
        goto done;
    }

    status = get_pgd_pae(vmi, &ctx, info);
    if (status != VMI_SUCCESS) {
        goto done;
    }

    if (!ENTRY_PRESENT(vmi->x86.transition_pages, info->x86_pae.pgd_value)) {
        status = VMI_FAILURE;
        goto done;
    }

    if (PAGE_SIZE(info->x86_pae.pgd_value)) {
        info->paddr = get_large_paddr_pae(vaddr, info->x86_pae.pgd_value);
        info->size = VMI_PS_2MB;
        status = VMI_SUCCESS;
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 2MB page\n");
        goto done;
    }

    status = get_pte_pae(vmi, &ctx, info);
    if (status != VMI_SUCCESS) {
        goto done;
    }

    if (!ENTRY_PRESENT(vmi->x86.transition_pages, info->x86_pae.pte_value)) {
        status = VMI_FAILURE;
        goto done;
    }

    info->size = VMI_PS_4KB;
    info->paddr = get_paddr_pae(vaddr, info->x86_pae.pte_value);
    status = VMI_SUCCESS;

done:
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: paddr = 0x%.16"PRIx64"\n", info->paddr);

    if (valid_npm(npm)) {
        if (VMI_FAILURE == vmi_nested_pagetable_lookup(vmi, 0, 0, npt, npm, info->paddr, &info->naddr, NULL) )
            return VMI_FAILURE;

        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: naddr = 0x%.16"PRIx64"\n", info->naddr);
    }

    return status;
}

GSList* get_pages_nopae(vmi_instance_t vmi, addr_t npt, page_mode_t npm, addr_t dtb)
{

    addr_t pgd_location = dtb;
    uint8_t entry_size = 0x4;

    GSList *ret = NULL;

    uint32_t *pgd_page = g_try_malloc0(VMI_PS_4KB);
    uint32_t *pt_page = g_try_malloc0(entry_size * PTRS_PER_NOPAE_PGD);

    ACCESS_CONTEXT(ctx,
                   .npt = npt,
                   .npm = npm);

    ctx.addr = dtb;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, pgd_page, NULL)) {
        goto done;
    }

    uint32_t pgd_index;
    for (pgd_index = 0; pgd_index < PTRS_PER_NOPAE_PGD; pgd_index++, pgd_location += entry_size) {
        uint64_t pgd_base_vaddr = pgd_index * PTRS_PER_NOPAE_PGD * PTRS_PER_NOPAE_PTE * entry_size;

        uint32_t pgd_entry = pgd_page[pgd_index];

        if (ENTRY_PRESENT(vmi->os_type, pgd_entry)) {

            if (PAGE_SIZE(pgd_entry) && (VMI_FILE == vmi->mode || vmi->x86.pse)) {
                page_info_t *p = g_try_malloc0(sizeof(page_info_t));
                if ( !p )
                    goto done;

                p->vaddr = pgd_base_vaddr;
                p->pt = dtb;
                p->paddr = get_large_paddr_nopae(p->vaddr, pgd_base_vaddr);
                p->size = VMI_PS_4MB;
                p->x86_legacy.pgd_location = pgd_location;
                p->x86_legacy.pgd_value = pgd_entry;
                ret = g_slist_prepend(ret, p);
                continue;
            }

            uint32_t pte_location = ptba_base_nopae(pgd_entry);

            ctx.addr = pte_location;
            if (VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, pt_page, NULL))
                goto done;

            uint32_t pte_index;
            for (pte_index = 0; pte_index < PTRS_PER_NOPAE_PTE; pte_index++, pte_location += entry_size) {
                uint32_t pte_entry = pt_page[pte_index];

                if (ENTRY_PRESENT(vmi->os_type, pte_entry)) {
                    page_info_t *p = g_try_malloc0(sizeof(page_info_t));
                    if ( !p )
                        goto done;

                    p->vaddr = pgd_base_vaddr + pte_index * VMI_PS_4KB;
                    p->pt = dtb;
                    p->paddr = get_paddr_nopae(p->vaddr, pte_entry);
                    p->size = VMI_PS_4KB;
                    p->x86_legacy.pgd_location = pgd_location;
                    p->x86_legacy.pgd_value = pgd_entry;
                    p->x86_legacy.pte_location = pte_location;
                    p->x86_legacy.pte_value = pte_entry;
                    ret = g_slist_prepend(ret, p);
                }
            }
        }
    }

done:
    g_free(pt_page);
    g_free(pgd_page);

    return ret;
}

GSList* get_pages_pae(vmi_instance_t vmi, addr_t npt, page_mode_t npm, addr_t dtb)
{

    uint32_t pdpi_base = get_pdptb(dtb);
    uint8_t entry_size = 0x8;

    GSList *ret = NULL;

    uint64_t pdpi_table[PTRS_PER_PDPI];
    uint64_t *page_directory = NULL;
    uint64_t *page_table = NULL;

    ACCESS_CONTEXT(ctx,
                   .npt = npt,
                   .npm = npm);

    ctx.addr = pdpi_base;
    if (VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(pdpi_table), pdpi_table, NULL))
        return ret;

    page_directory = g_malloc(VMI_PS_4KB);
    if ( !page_directory )
        goto done;

    page_table = g_malloc(VMI_PS_4KB);
    if ( !page_table )
        goto done;

    uint32_t pdp_index = 0;
    uint64_t pdpi_location = pdpi_base;
    for (pdp_index = 0; pdp_index < PTRS_PER_PDPI; pdp_index++, pdpi_location += entry_size) {

        uint64_t pdp_base_va = pdp_index * PTRS_PER_PAE_PGD * PTRS_PER_PAE_PGD * PTRS_PER_PAE_PTE * entry_size;
        uint64_t pdp_entry = pdpi_table[pdp_index];

        if (!ENTRY_PRESENT(vmi->x86.transition_pages, pdp_entry)) {
            continue;
        }

        uint64_t pde_location = pdba_base_pae(pdp_entry);

        ctx.addr = pde_location;
        if (VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, page_directory, NULL))
            goto done;

        uint32_t pd_index = 0;
        for (pd_index = 0; pd_index < PTRS_PER_PAE_PGD; pd_index++, pde_location += entry_size) {
            uint64_t pd_base_va = pdp_base_va + (pd_index * PTRS_PER_PAE_PGD * PTRS_PER_PAE_PTE * entry_size);

            uint64_t pd_entry = page_directory[pd_index];

            if (ENTRY_PRESENT(vmi->os_type, pd_entry)) {

                if (PAGE_SIZE(pd_entry)) {
                    page_info_t *p = g_try_malloc0(sizeof(page_info_t));
                    if ( !p )
                        goto done;

                    p->vaddr = pd_base_va;
                    p->pt = dtb;
                    p->paddr = get_large_paddr_pae(p->vaddr, pd_entry);
                    p->size = VMI_PS_2MB;
                    p->x86_pae.pdpe_location = pdpi_location;
                    p->x86_pae.pdpe_value = pdp_entry;
                    p->x86_pae.pgd_location = pde_location;
                    p->x86_pae.pgd_value = pd_entry;
                    ret = g_slist_prepend(ret, p);
                    continue;
                }

                uint64_t pte_location = ptba_base_pae(pd_entry);

                ctx.addr = pte_location;
                if (VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, page_table, NULL))
                    goto done;

                uint32_t pt_index;
                for (pt_index = 0; pt_index < PTRS_PER_PAE_PTE; pt_index++, pte_location += entry_size) {
                    uint64_t pte_entry = page_table[pt_index];

                    if (ENTRY_PRESENT(vmi->os_type, pte_entry)) {
                        page_info_t *p = g_try_malloc0(sizeof(page_info_t));
                        if ( !p )
                            goto done;

                        p->vaddr = pd_base_va + pt_index * VMI_PS_4KB;
                        p->pt = dtb;
                        p->paddr = get_paddr_pae(p->vaddr, pte_entry);
                        p->size = VMI_PS_4KB;
                        p->x86_pae.pdpe_location = pdpi_location;
                        p->x86_pae.pdpe_value = pdp_entry;
                        p->x86_pae.pgd_location = pde_location;
                        p->x86_pae.pgd_value = pd_entry;
                        p->x86_pae.pte_location = pte_location;
                        p->x86_pae.pte_value = pte_entry;
                        ret = g_slist_prepend(ret, p);
                    }
                }

            }
        }
    }

done:
    g_free(page_directory);
    g_free(page_table);

    return ret;
}

status_t
intel_mem_access_sanity_check(vmi_mem_access_t page_access_flag)
{
    /*
     * Setting a page write-only or write-execute in EPT triggers and EPT misconfiguration error
     * which is unhandled by Xen (at least up to 4.3) and instantly crashes the domain on the first trigger.
     *
     * See Intel® 64 and IA-32 Architectures Software Developer’s Manual
     * 28.2.3.1 EPT Misconfigurations
     * AN EPT misconfiguration occurs if any of the following is identified while translating a guest-physical address:
     * * The value of bits 2:0 of an EPT paging-structure entry is either 010b (write-only) or 110b (write/execute).
     */
    if (page_access_flag == VMI_MEMACCESS_R || page_access_flag == VMI_MEMACCESS_RX) {
        errprint("%s error: can't set requested memory access, unsupported by EPT.\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

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
#include "arch/amd64.h"

/* PML4 Table  */
static inline
addr_t get_pml4_index (addr_t vaddr)
{
    return (vaddr & VMI_BIT_MASK(39,47)) >> 36;
}

static inline
status_t get_pml4e (vmi_instance_t vmi,
                    access_context_t *ctx,
                    page_info_t *info)
{
    ctx->addr = (info->pt & VMI_BIT_MASK(12,51)) | get_pml4_index(info->vaddr);

    if (VMI_FAILURE == vmi_read_64(vmi, ctx, &info->x86_ia32e.pml4e_value)) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: error reading pml4e_location = 0x%.16"PRIx64"\n", ctx->addr);
        return VMI_FAILURE;
    }

    info->x86_ia32e.pml4e_location = ctx->addr;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pml4e_location = 0x%.16"PRIx64"\n", info->x86_ia32e.pml4e_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pml4e_value = 0x%.16"PRIx64"\n", info->x86_ia32e.pml4e_value);
    return VMI_SUCCESS;
}

static inline
addr_t get_pdpt_index_ia32e (addr_t vaddr)
{
    return (vaddr & VMI_BIT_MASK(30,38)) >> 27;
}

static inline
status_t get_pdpte_ia32e (vmi_instance_t vmi,
                          access_context_t *ctx,
                          page_info_t *info)
{
    ctx->addr = (info->x86_ia32e.pml4e_value & VMI_BIT_MASK(12,51)) | get_pdpt_index_ia32e(info->vaddr);

    if (VMI_FAILURE == vmi_read_64(vmi, ctx, &info->x86_ia32e.pdpte_value)) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: failed to read pdpte_location = 0x%.16"PRIx64"\n", ctx->addr);
        return VMI_FAILURE;
    }

    info->x86_ia32e.pdpte_location = ctx->addr;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpte_location = 0x%.16"PRIx64"\n", info->x86_ia32e.pdpte_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pdpte_value = 0x%.16"PRIx64"\n", info->x86_ia32e.pdpte_value);
    return VMI_SUCCESS;
}

static inline
uint64_t get_pd_index_ia32e (addr_t vaddr)
{
    return (vaddr & VMI_BIT_MASK(21,29)) >> 18;
}

static inline
status_t get_pde_ia32e (vmi_instance_t vmi,
                        access_context_t *ctx,
                        page_info_t *info)
{
    ctx->addr = (info->x86_ia32e.pdpte_value & VMI_BIT_MASK(12,51)) | get_pd_index_ia32e(info->vaddr);

    if (VMI_FAILURE == vmi_read_64(vmi, ctx, &info->x86_ia32e.pgd_value)) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: failed to read pde_location = 0x%.16"PRIx64"\n", ctx->addr);
        return VMI_FAILURE;
    }

    info->x86_ia32e.pgd_location = ctx->addr;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pde_location = 0x%.16"PRIx64"\n", info->x86_ia32e.pgd_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pde_value= 0x%.16"PRIx64"\n", info->x86_ia32e.pgd_value);

    return VMI_SUCCESS;
}

static inline
uint64_t get_pt_index_ia32e (addr_t vaddr)
{
    return (vaddr & VMI_BIT_MASK(12,20)) >> 9;
}

static inline
status_t get_pte_ia32e (vmi_instance_t vmi,
                        access_context_t *ctx,
                        page_info_t *info)
{
    ctx->addr = (info->x86_ia32e.pgd_value & VMI_BIT_MASK(12,51)) | get_pt_index_ia32e(info->vaddr);

    if (VMI_FAILURE == vmi_read_64(vmi, ctx, &info->x86_ia32e.pte_value)) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: failed to read pte_location = 0x%.16"PRIx64"\n", ctx->addr);
        return VMI_FAILURE;
    }

    info->x86_ia32e.pte_location = ctx->addr;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_location = 0x%.16"PRIx64"\n", info->x86_ia32e.pte_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pte_value = 0x%.16"PRIx64"\n", info->x86_ia32e.pte_value);

    return VMI_SUCCESS;
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

status_t v2p_ia32e (vmi_instance_t vmi,
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
    info->pm = VMI_PM_IA32E;
    info->vaddr = vaddr;

    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: lookup addr = 0x%.16"PRIx64"\n", vaddr);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: npt = 0x%.16"PRIx64" npm = %"PRIu32"\n", npt, npm);
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: pt = 0x%.16"PRIx64"\n", pt);

    status = get_pml4e(vmi, &ctx, info);
    if (status != VMI_SUCCESS)
        goto done;

    if (!ENTRY_PRESENT(vmi->x86.transition_pages, info->x86_ia32e.pml4e_value)) {
        status = VMI_FAILURE;
        goto done;
    }

    status = get_pdpte_ia32e(vmi, &ctx, info);
    if (status != VMI_SUCCESS)
        goto done;

    if (!ENTRY_PRESENT(vmi->x86.transition_pages, info->x86_ia32e.pdpte_value)) {
        status = VMI_FAILURE;
        goto done;
    }

    if (PAGE_SIZE(info->x86_ia32e.pdpte_value)) { // pdpte maps a 1GB page
        info->size = VMI_PS_1GB;
        info->paddr = get_gigpage_ia32e(vaddr, info->x86_ia32e.pdpte_value);
        status = VMI_SUCCESS;
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 1GB page\n");
        goto done;
    }

    status = get_pde_ia32e(vmi, &ctx, info);
    if (status != VMI_SUCCESS)
        goto done;

    if (!ENTRY_PRESENT(vmi->x86.transition_pages, info->x86_ia32e.pgd_value)) {
        status = VMI_FAILURE;
        goto done;
    }

    if (PAGE_SIZE(info->x86_ia32e.pgd_value)) { // pde maps a 2MB page
        info->size = VMI_PS_2MB;
        info->paddr = get_2megpage_ia32e(vaddr, info->x86_ia32e.pgd_value);
        status = VMI_SUCCESS;
        dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: 2MB page\n");
        goto done;
    }

    status = get_pte_ia32e(vmi, &ctx, info);
    if (status != VMI_SUCCESS)
        goto done;

    if (!ENTRY_PRESENT(vmi->x86.transition_pages, info->x86_ia32e.pte_value)) {
        status = VMI_FAILURE;
        goto done;
    }

    info->size = VMI_PS_4KB;
    info->paddr = get_paddr_ia32e(vaddr, info->x86_ia32e.pte_value);
    status = VMI_SUCCESS;

done:
    dbprint(VMI_DEBUG_PTLOOKUP, "--PTLookup: paddr = 0x%.16"PRIx64"\n", info->paddr);

    if (valid_npm(npm) && VMI_FAILURE == vmi_nested_pagetable_lookup(vmi, 0, 0, npt, npm, info->paddr, &info->naddr, NULL) )
        return VMI_FAILURE;

    return status;
}

GSList* get_pages_ia32e(vmi_instance_t vmi, addr_t npt, page_mode_t npm, addr_t dtb)
{

    GSList *ret = NULL;
    uint8_t entry_size = 0x8;

#define IA32E_ENTRIES_PER_PAGE 0x200 // 0x1000/0x8

    uint64_t *pml4_page = g_malloc(VMI_PS_4KB);
    uint64_t *pdpt_page = g_try_malloc0(VMI_PS_4KB);
    uint64_t *pgd_page = g_try_malloc0(VMI_PS_4KB);
    uint64_t *pt_page = g_try_malloc0(VMI_PS_4KB);

    if ( !pml4_page || !pdpt_page || !pgd_page || !pt_page )
        goto done;

    addr_t pml4e_location = dtb & VMI_BIT_MASK(12,51);

    ACCESS_CONTEXT(ctx,
                   .npt = npt,
                   .npm = npm);

    ctx.addr = pml4e_location;
    if (VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, pml4_page, NULL))
        goto done;

    uint64_t pml4e_index;
    for (pml4e_index = 0; pml4e_index < IA32E_ENTRIES_PER_PAGE; pml4e_index++, pml4e_location += entry_size) {

        uint64_t pml4e_value = pml4_page[pml4e_index];

        if (!ENTRY_PRESENT(vmi->x86.transition_pages, pml4e_value)) {
            continue;
        }

        uint64_t pdpte_location = pml4e_value & VMI_BIT_MASK(12,51);

        ctx.addr = pdpte_location;
        if (VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, pdpt_page, NULL))
            goto done;

        uint64_t pdpte_index;
        for (pdpte_index = 0; pdpte_index < IA32E_ENTRIES_PER_PAGE; pdpte_index++, pdpte_location++) {

            uint64_t pdpte_value = pdpt_page[pdpte_index];

            if (!ENTRY_PRESENT(vmi->x86.transition_pages, pdpte_value)) {
                continue;
            }

            if (PAGE_SIZE(pdpte_value)) {
                page_info_t *info = g_try_malloc0(sizeof(page_info_t));
                if ( !info )
                    goto done;

                info->vaddr = canonical_addr((pml4e_index << 39) | (pdpte_index << 30));
                info->pt = dtb;
                info->paddr = get_gigpage_ia32e(info->vaddr, pdpte_value);
                info->size = VMI_PS_1GB;
                info->x86_ia32e.pml4e_location = pml4e_location;
                info->x86_ia32e.pml4e_value = pml4e_value;
                info->x86_ia32e.pdpte_location = pdpte_location;
                info->x86_ia32e.pdpte_value = pdpte_value;
                ret = g_slist_prepend(ret, info);
                continue;
            }

            uint64_t pgd_location = pdpte_value & VMI_BIT_MASK(12,51);

            ctx.addr = pgd_location;
            if (VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, pgd_page, NULL))
                goto done;

            uint64_t pgde_index;
            for (pgde_index = 0; pgde_index < IA32E_ENTRIES_PER_PAGE; pgde_index++, pgd_location += entry_size) {

                uint64_t pgd_value = pgd_page[pgde_index];

                if (ENTRY_PRESENT(vmi->os_type, pgd_value)) {

                    if (PAGE_SIZE(pgd_value)) {
                        page_info_t *info = g_try_malloc0(sizeof(page_info_t));
                        if ( !info )
                            goto done;

                        info->vaddr = canonical_addr((pml4e_index << 39) | (pdpte_index << 30) |
                                                     (pgde_index << 21));
                        info->pt = dtb;
                        info->paddr = get_2megpage_ia32e(info->vaddr, pgd_value);
                        info->size = VMI_PS_2MB;
                        info->x86_ia32e.pml4e_location = pml4e_location;
                        info->x86_ia32e.pml4e_value = pml4e_value;
                        info->x86_ia32e.pdpte_location = pdpte_location;
                        info->x86_ia32e.pdpte_value = pdpte_value;
                        info->x86_ia32e.pgd_location = pgd_location;
                        info->x86_ia32e.pgd_value = pgd_value;
                        ret = g_slist_prepend(ret, info);
                        continue;
                    }

                    uint64_t pte_location = (pgd_value & VMI_BIT_MASK(12,51));
                    ctx.addr = pte_location;
                    if (VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, pt_page, NULL))
                        goto done;

                    uint64_t pte_index;
                    for (pte_index = 0; pte_index < IA32E_ENTRIES_PER_PAGE; pte_index++, pte_location += entry_size) {
                        uint64_t pte_value = pt_page[pte_index];

                        if (ENTRY_PRESENT(vmi->os_type, pte_value)) {
                            page_info_t *info = g_try_malloc0(sizeof(page_info_t));
                            if ( !info )
                                goto done;

                            info->vaddr = canonical_addr((pml4e_index << 39) | (pdpte_index << 30) |
                                                         (pgde_index << 21) | (pte_index << 12));
                            info->pt = dtb;
                            info->paddr = get_paddr_ia32e(info->vaddr, pte_value);
                            info->size = VMI_PS_4KB;
                            info->x86_ia32e.pml4e_location = pml4e_location;
                            info->x86_ia32e.pml4e_value = pml4e_value;
                            info->x86_ia32e.pdpte_location = pdpte_location;
                            info->x86_ia32e.pdpte_value = pdpte_value;
                            info->x86_ia32e.pgd_location = pgd_location;
                            info->x86_ia32e.pgd_value = pgd_value;
                            info->x86_ia32e.pte_location = pte_location;
                            info->x86_ia32e.pte_value = pte_value;
                            ret = g_slist_prepend(ret, info);
                            continue;
                        }
                    }
                }
            }
        }
    }

done:
    g_free(pt_page);
    g_free(pgd_page);
    g_free(pdpt_page);
    g_free(pml4_page);

    return ret;
}

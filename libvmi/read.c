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

#include <string.h>

#include "private.h"
#include "driver/driver_wrapper.h"

///////////////////////////////////////////////////////////
// Classic read functions for access to memory


status_t
vmi_mmap_guest(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t num_pages,
    int prot,
    void **access_ptrs)
{
    status_t ret = VMI_FAILURE;
    addr_t dtb = ctx->dtb;
    addr_t addr = ctx->addr;
    addr_t paddr;
    addr_t naddr;
    addr_t npt = ctx->npt;
    page_mode_t pm = ctx->pm;
    page_mode_t npm = ctx->npm;
    size_t buf_offset = 0;
    unsigned long *pfns = NULL;
    unsigned int pfn_ndx = 0, i;

    switch (ctx->translate_mechanism) {
        case VMI_TM_KERNEL_SYMBOL:
#ifdef ENABLE_SAFETY_CHECKS
            if (!vmi->os_interface || !vmi->kpgd)
                goto done;
#endif
            if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, ctx->ksym, &addr) )
                goto done;

            if (!pm)
                pm = vmi->page_mode;

            dtb = vmi->kpgd;

            break;
        case VMI_TM_PROCESS_PID:
#ifdef ENABLE_SAFETY_CHECKS
            if (!vmi->os_interface)
                goto done;
#endif

            if ( !ctx->pid )
                dtb = vmi->kpgd;
            else if (ctx->pid > 0) {
                if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, ctx->pid, &dtb) )
                    goto done;
            }

            if (!pm)
                pm = vmi->page_mode;
            if (!dtb)
                goto done;
            break;
        case VMI_TM_PROCESS_DTB:
            if (!pm)
                pm = vmi->page_mode;
            break;
        default:
            errprint("%s error: translation mechanism is not defined or unsupported.\n", __FUNCTION__);
            goto done;
    }

    pfns = calloc(num_pages, sizeof(unsigned long));
    if (!pfns)
        goto done;

    for (i = 0; i < num_pages; i++) {
        if (VMI_SUCCESS == vmi_nested_pagetable_lookup(vmi, npt, npm, dtb, pm, addr + buf_offset, &paddr, &naddr)) {

            if (valid_npm(npm))
                paddr = naddr;

            pfns[pfn_ndx] = paddr >> vmi->page_shift;
            // store relative offsets to the appropriate pages
            access_ptrs[i] = (void *)((addr_t)pfn_ndx * vmi->page_size);
            ++pfn_ndx;
        } else {
            // missing page, mapping failed
            access_ptrs[i] = (void *)-1;
        }

        buf_offset += vmi->page_size;
    }

    void *base_ptr = NULL;
    // do mmap only if there are pages available for mapping
    if (pfn_ndx != 0) {
        if (driver_mmap_guest(vmi, pfns, pfn_ndx, prot, &base_ptr) != VMI_SUCCESS) {
            dbprint(VMI_DEBUG_READ, "--failed to mmap guest memory");
            goto done;
        }
    }

    for (i = 0; i < num_pages; i++) {
        if (access_ptrs[i] != (void *)-1) {
            // add buffer base pointer to the relative offsets since now we know its value
            access_ptrs[i] += (addr_t)base_ptr;
        } else {
            access_ptrs[i] = NULL;
        }
    }

    ret = VMI_SUCCESS;

done:
    if (pfns) {
        free(pfns);
    }

    return ret;
}

static status_t
determine_contiguous_region(vmi_instance_t vmi, GSList *region_start, GArray *pfns, size_t max_remaining_pages,
                            GSList **region_end)
{
    for (GSList *elem = region_start, *prev_elem = region_start; elem != NULL; prev_elem = elem, elem = elem->next, *region_end = elem) {
        page_info_t *prev_elem_info = prev_elem->data;
        page_info_t *cur_elem_info = elem->data;

        // Break if we encounter the end of a contiguous region
        if (cur_elem_info->vaddr - prev_elem_info->vaddr > prev_elem_info->size) {
            break;
        }

        // Add pfns to pfn array. Split large pages into 4kb pages while also making sure that we don't overshoot
        // by splitting a whole large page although the requested range ends somewhere within that page.
        for (size_t i = 0; i < cur_elem_info->size / vmi->page_size && pfns->len < max_remaining_pages; i++) {
            addr_t current_pfn = (cur_elem_info->paddr >> vmi->page_shift) + i;

            if (!g_array_append_val(pfns, current_pfn)) {
                errprint("--%s: Unable to resize array\n", __func__);
                return VMI_FAILURE;
            }
        }

        if (pfns->len >= max_remaining_pages) {
            break;
        }
    }

    return VMI_SUCCESS;
}

status_t
vmi_mmap_guest_2(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t num_pages,
    int prot,
    mapped_regions_t *mapped_regions)
{
    status_t ret = VMI_FAILURE;
    addr_t dtb = ctx->dtb;
    addr_t addr = ctx->addr;
    addr_t npt = ctx->npt;
    page_mode_t pm = ctx->pm;
    page_mode_t npm = ctx->npm;
    GArray *pfns = NULL;
    GArray* result = NULL;

    switch (ctx->translate_mechanism) {
        case VMI_TM_KERNEL_SYMBOL:
#ifdef ENABLE_SAFETY_CHECKS
            if (!vmi->os_interface || !vmi->kpgd)
                return VMI_FAILURE;
#endif
            if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, ctx->ksym, &addr) )
                return VMI_FAILURE;

            if (!pm)
                pm = vmi->page_mode;

            dtb = vmi->kpgd;

            break;
        case VMI_TM_PROCESS_PID:
#ifdef ENABLE_SAFETY_CHECKS
            if (!vmi->os_interface)
                return VMI_FAILURE;
#endif

            if ( !ctx->pid )
                dtb = vmi->kpgd;
            else if (ctx->pid > 0) {
                if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, ctx->pid, &dtb) )
                    return VMI_FAILURE;
            }

            if (!pm)
                pm = vmi->page_mode;
            if (!dtb)
                return VMI_FAILURE;
            break;
        case VMI_TM_PROCESS_DTB:
            if (!pm)
                pm = vmi->page_mode;
            break;
        default:
            errprint("%s error: translation mechanism is not defined or unsupported.\n", __FUNCTION__);
            return VMI_FAILURE;
    }

    GSList *va_pages = vmi_get_nested_va_pages_subset(vmi, npt, npm, dtb, pm, addr, addr + num_pages * vmi->page_size);
    if (!va_pages) {
        mapped_regions->size = 0;
        mapped_regions->regions = NULL;
        return VMI_SUCCESS;
    }

    pfns = g_array_new(false, false, sizeof(unsigned long));
    if (!pfns) {
        errprint("--%s: unable to initialize new GArray\n", __FUNCTION__);
        goto done;
    }

    result = g_array_new(false, false, sizeof(mapped_region_t));
    if (!result) {
        goto done;
    }

    va_pages = g_slist_reverse(va_pages);

    for (GSList* elem = va_pages; elem != NULL && num_pages > 0;) {
        mapped_region_t cur_region = {0};
        cur_region.start_va = ((page_info_t *) elem->data)->vaddr;

        // determine the next region of contiguous virtual addresses and retrieve their respective pfns
        if (determine_contiguous_region(vmi, elem, pfns, num_pages, &elem) == VMI_FAILURE)
            goto done;
        num_pages -= pfns->len;
        cur_region.num_pages = pfns->len;

        status_t mmap_result = driver_mmap_guest(vmi, (unsigned long *) pfns->data, pfns->len, prot, &cur_region.access_ptr);

        // Reset array length so the array can be reused without having to reallocate
        pfns->len = 0;

        // In some cases v2p translations may be incorrect possibly due to incomplete pte resolving.
        // Therefore, we skip over regions we couldn't map successfully.
        if (mmap_result == VMI_FAILURE) {
            dbprint(VMI_DEBUG_READ, "--failed to mmap guest memory");
            continue;
        }

        if (!g_array_append_val(result, cur_region)) {
            errprint("--%s: Unable to resize array\n", __func__);
            goto done;
        }
    }

    mapped_regions->size = result->len;
    mapped_regions->regions = (mapped_region_t *) g_array_free(result, false);
    result = NULL;

    ret = VMI_SUCCESS;

done:
    if (va_pages) {
        g_slist_free(va_pages);
    }

    if (pfns) {
        g_array_free(pfns, true);
    }

    if (result) {
        g_array_free(result, true);
    }

    return ret;
}

void vmi_free_mapped_regions(vmi_instance_t vmi, const mapped_regions_t *mapped_regions)
{
    if (mapped_regions && mapped_regions->regions) {
        for (size_t i = 0; i < mapped_regions->size; i++) {
            if (mapped_regions->regions[i].access_ptr)
                if (munmap(mapped_regions->regions[i].access_ptr, mapped_regions->regions[i].num_pages << vmi->page_shift))
                    dbprint(VMI_DEBUG_READ, "--failed to unmap region");
        }
        g_free(mapped_regions->regions);
    }
}

status_t
vmi_mmap_guest_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    size_t num_pages,
    int prot,
    void **access_ptrs)
{
    status_t ret = VMI_FAILURE;
    unsigned long *pfns = NULL;
    void *base_ptr = NULL;
    unsigned int i;

    pfns = calloc(num_pages, sizeof(unsigned long));
    if (!pfns)
        goto done;

    for (i = 0; i < num_pages; i++)
        pfns[i] = (paddr + ((addr_t)i * vmi->page_size)) >> vmi->page_shift;

    if (VMI_FAILURE == driver_mmap_guest(vmi, pfns, num_pages, prot, &base_ptr)) {
        dbprint(VMI_DEBUG_READ, "--failed to mmap guest memory");
        goto done;
    }

    for (i = 0; i < num_pages; i++)
        access_ptrs[i] = base_ptr + ((addr_t)i * vmi->page_size);

    ret = VMI_SUCCESS;

done:
    if (pfns)
        free(pfns);

    return ret;
}

status_t
vmi_read(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t count,
    void *buf,
    size_t *bytes_read)
{
    status_t ret = VMI_FAILURE;
    size_t buf_offset = 0;
    unsigned char *memory;
    addr_t start_addr;
    addr_t paddr;
    addr_t naddr;
    addr_t pfn;
    addr_t offset;
    addr_t pt;
    page_mode_t pm;

#ifdef ENABLE_SAFETY_CHECKS
    if (NULL == vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL, returning without read\n", __FUNCTION__);
        goto done;
    }

    if (NULL == ctx) {
        dbprint(VMI_DEBUG_READ, "--%s: ctx passed as NULL, returning without read\n", __FUNCTION__);
        goto done;
    }

    if (NULL == buf) {
        dbprint(VMI_DEBUG_READ, "--%s: buf passed as NULL, returning without read\n", __FUNCTION__);
        goto done;
    }

    if (ctx->version != ACCESS_CONTEXT_VERSION) {
        if (!vmi->actx_version_warn_once)
            errprint("--%s: access context version mismatch, please update your code\n", __FUNCTION__);
        vmi->actx_version_warn_once = 1;

        // TODO: for compatibility reasons we still accept code compiled
        //       without the ABI version field initialized.
        //       Turn this check into enforcement after appropriate amount of
        //       time passed (in ~2023 or after).
    }
#endif

    // Set defaults
    pt = ctx->pt;
    pm = ctx->pm;
    start_addr = ctx->addr;

    switch (ctx->tm) {
        case VMI_TM_NONE:
            pm = VMI_PM_NONE;
            pt = 0;
            break;
        case VMI_TM_KERNEL_SYMBOL:
#ifdef ENABLE_SAFETY_CHECKS
            if (!vmi->os_interface || !vmi->kpgd)
                goto done;
#endif
            if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, ctx->ksym, &start_addr) )
                goto done;

            pt = vmi->kpgd;
            if (!pm)
                pm = vmi->page_mode;

            break;
        case VMI_TM_PROCESS_PID:
#ifdef ENABLE_SAFETY_CHECKS
            if (!vmi->os_interface)
                goto done;
#endif

            if ( !ctx->pid )
                pt = vmi->kpgd;
            else if (ctx->pid > 0) {
                if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, ctx->pid, &pt) )
                    goto done;
            }
            if (!pm)
                pm = vmi->page_mode;
            if (!pt)
                goto done;
            break;
        case VMI_TM_PROCESS_DTB:
            if (!pm)
                pm = vmi->page_mode;
            break;
        default:
            errprint("%s error: translation mechanism is not defined.\n", __FUNCTION__);
            goto done;
    }

#ifdef ENABLE_SAFETY_CHECKS
    if (pt && !valid_pm(pm)) {
        dbprint(VMI_DEBUG_READ, "--%s: pagetable specified with no page mode\n", __FUNCTION__);
        goto done;
    }

    if (ctx->npt && !valid_npm(ctx->npm)) {
        dbprint(VMI_DEBUG_READ, "--%s: nested pagetable specified with no nested page mode\n", __FUNCTION__);
        goto done;
    }
#endif

    while (count > 0) {
        size_t read_len = 0;

        if (valid_pm(pm)) {
            if (VMI_SUCCESS != vmi_nested_pagetable_lookup(vmi, ctx->npt, ctx->npm, pt, pm, start_addr + buf_offset, &paddr, &naddr))
                goto done;

            if (valid_npm(ctx->npm)) {
                dbprint(VMI_DEBUG_READ, "--Setting paddr to nested address 0x%lx\n", naddr);
                paddr = naddr;
            }
        } else {
            paddr = start_addr + buf_offset;

            if (valid_npm(ctx->npm) && VMI_SUCCESS != vmi_nested_pagetable_lookup(vmi, 0, 0, ctx->npt, ctx->npm, paddr, &paddr, NULL) )
                goto done;
        }

        /* access the memory */
        pfn = paddr >> vmi->page_shift;
        dbprint(VMI_DEBUG_READ, "--Reading pfn 0x%lx\n", pfn);

        offset = (vmi->page_size - 1) & paddr;
        memory = vmi_read_page(vmi, pfn);

        if (NULL == memory)
            goto done;

        /* determine how much we can read */
        if ((offset + count) > vmi->page_size)
            read_len = vmi->page_size - offset;
        else
            read_len = count;

        /* do the read */
        memcpy(((char *) buf) + (addr_t) buf_offset, memory + (addr_t) offset, read_len);

        /* set variables for next loop */
        count -= read_len;
        buf_offset += read_len;
    }

    ret = VMI_SUCCESS;

done:
    if ( bytes_read )
        *bytes_read = buf_offset;

    return ret;
}

// Reads memory at a guest's physical address
status_t
vmi_read_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    size_t count,
    void *buf,
    size_t *bytes_read)
{
    ACCESS_CONTEXT(ctx, .addr = paddr);
    return vmi_read(vmi, &ctx, count, buf, bytes_read);
}

status_t
vmi_read_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    size_t count,
    void *buf,
    size_t *bytes_read)
{
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_PID,
                   .addr = vaddr,
                   .pid = pid);

    return vmi_read(vmi, &ctx, count, buf, bytes_read);
}

status_t
vmi_read_ksym(
    vmi_instance_t vmi,
    const char *sym,
    size_t count,
    void *buf,
    size_t *bytes_read)
{
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_KERNEL_SYMBOL,
                   .pm = vmi->page_mode,
                   .ksym = sym);

    return vmi_read(vmi, &ctx, count, buf, bytes_read);
}

///////////////////////////////////////////////////////////
// Easy access to memory
status_t
vmi_read_8(vmi_instance_t vmi,
           const access_context_t *ctx,
           uint8_t * value)
{
    return vmi_read(vmi, ctx, 1, value, NULL);
}

status_t
vmi_read_16(vmi_instance_t vmi,
            const access_context_t *ctx,
            uint16_t * value)
{
    return vmi_read(vmi, ctx, 2, value, NULL);
}

status_t
vmi_read_32(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint32_t * value)
{
    return vmi_read(vmi, ctx, 4, value, NULL);
}

status_t
vmi_read_64(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint64_t * value)
{
    return vmi_read(vmi, ctx, 8, value, NULL);
}

status_t
vmi_read_addr(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t *value)
{
    status_t ret = VMI_FAILURE;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    switch (vmi->page_mode) {
        case VMI_PM_AARCH64:// intentional fall-through
        case VMI_PM_IA32E:
            ret = vmi_read(vmi, ctx, 8, value, NULL);
            break;
        case VMI_PM_AARCH32:// intentional fall-through
        case VMI_PM_LEGACY: // intentional fall-through
        case VMI_PM_PAE: {
            uint32_t tmp = 0;
            ret = vmi_read(vmi, ctx, 4, &tmp, NULL);
            *value = 0;
            *value = (addr_t) tmp;
            break;
        }
        default:
            dbprint(VMI_DEBUG_READ, "--%s: unknown page mode, can't read addr as width is unknown", __FUNCTION__);
            break;
    }

    return ret;
}

char *
vmi_read_str(
    vmi_instance_t vmi,
    const access_context_t *ctx)
{
    access_context_t _ctx = *ctx;
    addr_t len = 0;
    uint8_t buf[VMI_PS_4KB];
    size_t bytes_read;
    bool read_more = 1;
    char *ret = NULL;

    do {
        size_t offset = _ctx.addr & VMI_BIT_MASK(0,11);
        size_t read_size = VMI_PS_4KB - offset;

        dbprint(VMI_DEBUG_READ, "--start to read string from 0x%lx, page offset 0x%lx, read: %lu\n",
                _ctx.addr, offset, read_size);

        if (VMI_FAILURE == vmi_read(vmi, &_ctx, read_size, (void*)&buf, &bytes_read) &&
                !bytes_read) {
            return ret;
        }

        /* Count new non-null characters */
        size_t read_len = 0;
        for (read_len = 0; read_len < bytes_read; read_len++) {
            if (buf[read_len] == '\0') {
                read_more = 0;
                break;
            }
        }

        /*
         * Realloc, tack on the '\0' in case of errors and
         * get ready to read the next page.
         */
        char *_ret = realloc(ret, len + read_len + 1);
        if ( !_ret )
            return ret;

        ret = _ret;
        memcpy(&ret[len], &buf, read_len);
        len += read_len;
        ret[len] = '\0';
        _ctx.addr += read_len;
    } while (read_more);

    return ret;
}

uint16_t *
vmi_read_wstr(
    vmi_instance_t vmi,
    const access_context_t *ctx)
{
    access_context_t _ctx = *ctx;
    addr_t len = 0;
    uint8_t buf[VMI_PS_4KB];
    size_t bytes_read;
    bool read_more = 1;
    uint16_t *ret = NULL;

    do {
        size_t offset = _ctx.addr & VMI_BIT_MASK(0,11);
        size_t read_size = VMI_PS_4KB - offset;

        dbprint(VMI_DEBUG_READ, "--start to read string from 0x%lx, page offset 0x%lx, read: %lu\n",
                _ctx.addr, offset, read_size);

        if (VMI_FAILURE == vmi_read(vmi, &_ctx, read_size, (void*)&buf, &bytes_read) &&
                !bytes_read) {
            return ret;
        }

        /* Count new non-null characters */
        size_t read_len = 0;
        for (read_len = 0; read_len + 1 < bytes_read; read_len += 2) {
            if (buf[read_len] == 0 && buf[read_len + 1] == 0) {
                read_more = 0;
                break;
            }
        }

        /*
         * Realloc, tack on the L'\0' in case of errors and
         * get ready to read the next page.
         */
        uint16_t *_ret = realloc(ret, len + read_len + 2);
        if ( !_ret )
            return ret;

        ret = _ret;
        memcpy(&ret[len / 2], &buf, read_len);
        len += read_len;
        ret[len / 2] = 0;
        _ctx.addr += read_len;
    } while (read_more);

    return ret;
}

unicode_string_t*
vmi_read_unicode_str(
    vmi_instance_t vmi,
    const access_context_t *ctx)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL, returning without read",
                __FUNCTION__);
        return NULL;
    }
    if (!vmi->os_interface || !vmi->os_interface->os_read_unicode_struct)
        return NULL;
#endif

    return vmi->os_interface->os_read_unicode_struct(vmi, ctx);
}

unicode_string_t*
vmi_read_unicode_str_pm(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    page_mode_t mode )
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL, returning without read",
                __FUNCTION__);
        return NULL;
    }
    if (!vmi->os_interface || !vmi->os_interface->os_read_unicode_struct_pm)
        return NULL;
#endif

    return vmi->os_interface->os_read_unicode_struct_pm(vmi, ctx, mode);
}

///////////////////////////////////////////////////////////
// Easy access to physical memory
status_t
vmi_read_8_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint8_t * value)
{
    return vmi_read_pa(vmi, paddr, 1, value, NULL);
}

status_t
vmi_read_16_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint16_t * value)
{
    return vmi_read_pa(vmi, paddr, 2, value, NULL);
}

status_t
vmi_read_32_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t * value)
{
    return vmi_read_pa(vmi, paddr, 4, value, NULL);
}

status_t
vmi_read_64_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint64_t * value)
{
    return vmi_read_pa(vmi, paddr, 8, value, NULL);
}

status_t
vmi_read_addr_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    addr_t *value)
{
    status_t ret = VMI_FAILURE;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL, returning without read",
                __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    switch (vmi->page_mode) {
        case VMI_PM_AARCH64:// intentional fall-through
        case VMI_PM_IA32E:
            ret = vmi_read_pa(vmi, paddr, 8, value, NULL);
            break;
        case VMI_PM_AARCH32:// intentional fall-through
        case VMI_PM_LEGACY: // intentional fall-through
        case VMI_PM_PAE: {
            uint32_t tmp = 0;
            ret = vmi_read_pa(vmi, paddr, 4, &tmp, NULL);
            *value = 0;
            *value = (addr_t) tmp;
            break;
        }
        default:
            dbprint(VMI_DEBUG_READ,
                    "--%s: unknown page mode, can't read addr as width is unknown",
                    __FUNCTION__);
            break;
    }

    return ret;
}

char *
vmi_read_str_pa(
    vmi_instance_t vmi,
    addr_t paddr)
{
    ACCESS_CONTEXT(ctx, .addr = paddr);
    return vmi_read_str(vmi, &ctx);
}

uint16_t *
vmi_read_wstr_pa(
    vmi_instance_t vmi,
    addr_t paddr)
{
    ACCESS_CONTEXT(ctx, .addr = paddr);
    return vmi_read_wstr(vmi, &ctx);
}

///////////////////////////////////////////////////////////
// Easy access to virtual memory
status_t
vmi_read_8_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint8_t * value)
{
    return vmi_read_va(vmi, vaddr, pid, 1, value, NULL);
}

status_t
vmi_read_16_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint16_t * value)
{
    return vmi_read_va(vmi, vaddr, pid, 2, value, NULL);
}

status_t
vmi_read_32_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint32_t * value)
{
    return vmi_read_va(vmi, vaddr, pid, 4, value, NULL);
}

status_t
vmi_read_64_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint64_t * value)
{
    return vmi_read_va(vmi, vaddr, pid, 8, value, NULL);
}

status_t
vmi_read_addr_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    addr_t *value)
{
    status_t ret = VMI_FAILURE;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL, returning without read",
                __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    switch (vmi->page_mode) {
        case VMI_PM_AARCH64:// intentional fall-through
        case VMI_PM_IA32E:
            ret = vmi_read_va(vmi, vaddr, pid, 8, value, NULL);
            break;
        case VMI_PM_AARCH32:// intentional fall-through
        case VMI_PM_LEGACY: // intentional fall-through
        case VMI_PM_PAE: {
            uint32_t tmp = 0;
            ret = vmi_read_va(vmi, vaddr, pid, 4, &tmp, NULL);
            *value = 0;
            *value = (addr_t) tmp;
            break;
        }
        default:
            dbprint(VMI_DEBUG_READ,
                    "--%s: unknown page mode, can't read addr as width is unknown",
                    __FUNCTION__);
            break;
    }

    return ret;
}

char *
vmi_read_str_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid)
{
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_PID,
                   .addr = vaddr,
                   .pid = pid);

    return vmi_read_str(vmi, &ctx);
}

uint16_t *
vmi_read_wstr_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid)
{
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_PID,
                   .addr = vaddr,
                   .pid = pid);

    return vmi_read_wstr(vmi, &ctx);
}

unicode_string_t *
vmi_read_unicode_str_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid)
{
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_PID,
                   .addr = vaddr,
                   .pid = pid);

    return vmi_read_unicode_str(vmi, &ctx);
}

///////////////////////////////////////////////////////////
// Easy access to memory using kernel symbols
status_t
vmi_read_8_ksym(
    vmi_instance_t vmi,
    const char *sym,
    uint8_t * value)
{
    return vmi_read_ksym(vmi, sym, 1, value, NULL);
}

status_t
vmi_read_16_ksym(
    vmi_instance_t vmi,
    const char *sym,
    uint16_t * value)
{
    return vmi_read_ksym(vmi, sym, 2, value, NULL);
}

status_t
vmi_read_32_ksym(
    vmi_instance_t vmi,
    const char *sym,
    uint32_t * value)
{
    return vmi_read_ksym(vmi, sym, 4, value, NULL);
}

status_t
vmi_read_64_ksym(
    vmi_instance_t vmi,
    const char *sym,
    uint64_t * value)
{
    return vmi_read_ksym(vmi, sym, 8, value, NULL);
}

status_t
vmi_read_addr_ksym(
    vmi_instance_t vmi,
    const char *sym,
    addr_t *value)
{
    status_t ret = VMI_FAILURE;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL, returning without read",
                __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    switch (vmi->page_mode) {
        case VMI_PM_AARCH64:// intentional fall-through
        case VMI_PM_IA32E:
            ret = vmi_read_ksym(vmi, sym, 8, value, NULL);
            break;
        case VMI_PM_AARCH32:// intentional fall-through
        case VMI_PM_LEGACY: // intentional fall-through
        case VMI_PM_PAE: {
            uint32_t tmp = 0;
            ret = vmi_read_ksym(vmi, sym, 4, &tmp, NULL);
            *value = 0;
            *value = (addr_t) tmp;
            break;
        }
        default:
            dbprint(VMI_DEBUG_READ,
                    "--%s: unknown page mode, can't read addr as width is unknown",
                    __FUNCTION__);
            break;
    }

    return ret;
}

char *
vmi_read_str_ksym(
    vmi_instance_t vmi,
    const char *sym)
{
    addr_t vaddr = 0;

    if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, sym, &vaddr) )
        return NULL;

    return vmi_read_str_va(vmi, vaddr, 0);
}

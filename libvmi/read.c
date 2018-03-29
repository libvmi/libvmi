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
#include <wchar.h>
#include <errno.h>

#include "private.h"
#include "driver/driver_wrapper.h"

///////////////////////////////////////////////////////////
// Classic read functions for access to memory
status_t
vmi_read(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t count,
    void *buf,
    size_t *bytes_read)
{
    status_t ret = VMI_FAILURE;
    unsigned char *memory = NULL;
    addr_t start_addr = 0;
    addr_t paddr = 0;
    addr_t pfn = 0;
    addr_t offset = 0;
    addr_t dtb = 0;
    size_t buf_offset = 0;

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

    switch (ctx->translate_mechanism) {
        case VMI_TM_NONE:
            start_addr = ctx->addr;
            break;
        case VMI_TM_KERNEL_SYMBOL:
            if (!vmi->arch_interface || !vmi->os_interface || !vmi->kpgd)
                goto done;

            dtb = vmi->kpgd;
            if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, ctx->ksym, &start_addr) )
                goto done;
            break;
        case VMI_TM_PROCESS_PID:
            if (!vmi->arch_interface || !vmi->os_interface)
                goto done;

            if ( !ctx->pid )
                dtb = vmi->kpgd;
            else if (ctx->pid > 0) {
                if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, ctx->pid, &dtb) )
                    goto done;
            }

            if (!dtb)
                goto done;

            start_addr = ctx->addr;
            break;
        case VMI_TM_PROCESS_DTB:
            if (!vmi->arch_interface)
                goto done;

            dtb = ctx->dtb;
            start_addr = ctx->addr;
            break;
        default:
            errprint("%s error: translation mechanism is not defined.\n", __FUNCTION__);
            goto done;
    }


    while (count > 0) {
        size_t read_len = 0;

        if (dtb) {
            if (VMI_SUCCESS != vmi_pagetable_lookup_cache(vmi, dtb, start_addr + buf_offset, &paddr))
                goto done;
        } else {
            paddr = start_addr + buf_offset;
        }


        /* access the memory */
        pfn = paddr >> vmi->page_shift;
        offset = (vmi->page_size - 1) & paddr;
        memory = vmi_read_page(vmi, pfn);
        if (NULL == memory)
            goto done;

        /* determine how much we can read */
        if ((offset + count) > vmi->page_size) {
            read_len = vmi->page_size - offset;
        } else {
            read_len = count;
        }

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
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_NONE,
        .addr = paddr
    };

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
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = vaddr,
        .pid = pid
    };

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
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_KERNEL_SYMBOL,
        .ksym = sym,
    };

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

    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL", __FUNCTION__);
        return VMI_FAILURE;
    }

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
    unsigned char *memory = NULL;
    char *rtnval = NULL;
    addr_t addr = 0;
    addr_t dtb = 0;
    addr_t paddr = 0;
    addr_t pfn = 0;
    addr_t offset = 0;
    int len = 0;
    size_t read_len = 0;
    int read_more = 1;

    rtnval = NULL;

    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL, returning without read",
                __FUNCTION__);
        return NULL;
    }
    if (!ctx) {
        dbprint(VMI_DEBUG_READ, "--%s: ctx passed as NULL, returning without read",
                __FUNCTION__);
        return NULL;
    }

    switch (ctx->translate_mechanism) {
        case VMI_TM_NONE:
            addr = ctx->addr;
            break;
        case VMI_TM_KERNEL_SYMBOL:
            if (!vmi->arch_interface || !vmi->os_interface || !vmi->kpgd)
                return NULL;

            dtb = vmi->kpgd;
            if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, ctx->ksym, &addr) )
                return NULL;
            break;
        case VMI_TM_PROCESS_PID:
            if ( !ctx->pid )
                dtb = vmi->kpgd;
            else if ( ctx->pid > 0) {
                if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, ctx->pid, &dtb) )
                    return NULL;
            }

            if (!dtb)
                return NULL;

            addr = ctx->addr;
            break;
        case VMI_TM_PROCESS_DTB:
            dtb = ctx->dtb;
            addr = ctx->addr;
            break;
        default:
            errprint("%s error: translation mechanism is not defined.\n", __FUNCTION__);
            return NULL;
    }

    while (read_more) {

        addr += len;
        if (dtb) {
            if (VMI_SUCCESS != vmi_pagetable_lookup_cache(vmi, dtb, addr, &paddr)) {
                return rtnval;
            }
        } else {
            paddr = addr;
        }

        /* access the memory */
        pfn = paddr >> vmi->page_shift;
        offset = (vmi->page_size - 1) & paddr;
        memory = vmi_read_page(vmi, pfn);
        if (NULL == memory) {
            return rtnval;
        }

        /* Count new non-null characters */
        read_len = 0;
        while (offset + read_len < vmi->page_size) {
            if (memory[offset + read_len] == '\0') {
                read_more = 0;
                break;
            }

            read_len++;
        }

        /* Otherwise, realloc, tack on the '\0' in case of errors and
         * get ready to read the next page.
         */
        rtnval = realloc(rtnval, len + 1 + read_len);
        memcpy(&rtnval[len], &memory[offset], read_len);
        len += read_len;
        rtnval[len] = '\0';
    }

    return rtnval;
}

unicode_string_t*
vmi_read_unicode_str(
    vmi_instance_t vmi,
    const access_context_t *ctx)
{
    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL, returning without read",
                __FUNCTION__);
        return NULL;
    }
    if (vmi->os_interface && vmi->os_interface->os_read_unicode_struct)
        return vmi->os_interface->os_read_unicode_struct(vmi, ctx);

    return NULL;
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

    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL, returning without read",
                __FUNCTION__);
        return VMI_FAILURE;
    }

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
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_NONE,
        .addr = paddr
    };

    return vmi_read_str(vmi, &ctx);
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

    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL, returning without read",
                __FUNCTION__);
        return VMI_FAILURE;
    }

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
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = vaddr,
        .pid = pid
    };

    return vmi_read_str(vmi, &ctx);
}

unicode_string_t *
vmi_read_unicode_str_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid)
{
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = vaddr,
        .pid = pid
    };

    return vmi_read_unicode_str(vmi, &ctx);
}

///////////////////////////////////////////////////////////
// Easy access to memory using kernel symbols
status_t
vmi_read_8_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint8_t * value)
{
    return vmi_read_ksym(vmi, sym, 1, value, NULL);
}

status_t
vmi_read_16_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint16_t * value)
{
    return vmi_read_ksym(vmi, sym, 2, value, NULL);
}

status_t
vmi_read_32_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint32_t * value)
{
    return vmi_read_ksym(vmi, sym, 4, value, NULL);
}

status_t
vmi_read_64_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint64_t * value)
{
    return vmi_read_ksym(vmi, sym, 8, value, NULL);
}

status_t
vmi_read_addr_ksym(
    vmi_instance_t vmi,
    char *sym,
    addr_t *value)
{
    status_t ret = VMI_FAILURE;

    if (!vmi) {
        dbprint(VMI_DEBUG_READ, "--%s: vmi passed as NULL, returning without read",
                __FUNCTION__);
        return VMI_FAILURE;
    }

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
    char *sym)
{
    addr_t vaddr = 0;

    if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, sym, &vaddr) )
        return NULL;

    return vmi_read_str_va(vmi, vaddr, 0);
}

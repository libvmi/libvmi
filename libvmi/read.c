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
size_t
vmi_read(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    void *buf,
    size_t count)
{
    unsigned char *memory = NULL;
    addr_t start_addr = 0;
    addr_t paddr = 0;
    addr_t pfn = 0;
    addr_t offset = 0;
    addr_t dtb = 0;
    size_t buf_offset = 0;

    if (NULL == ctx) {
        dbprint(VMI_DEBUG_READ, "--%s: ctx passed as NULL, returning without read\n", __FUNCTION__);
        return 0;
    }

    if (NULL == buf) {
        dbprint(VMI_DEBUG_READ, "--%s: buf passed as NULL, returning without read\n", __FUNCTION__);
        return 0;
    }

    switch (ctx->translate_mechanism) {
        case VMI_TM_NONE:
            start_addr = ctx->addr;
            break;
        case VMI_TM_KERNEL_SYMBOL:
            if (!vmi->arch_interface || !vmi->os_interface || !vmi->kpgd)
              return 0;

            dtb = vmi->kpgd;
            start_addr = vmi_translate_ksym2v(vmi, ctx->ksym);
            break;
        case VMI_TM_PROCESS_PID:
            if (!vmi->arch_interface || !vmi->os_interface) {
              return 0;
            }
            if(ctx->pid) {
                dtb = vmi_pid_to_dtb(vmi, ctx->pid);
            } else {
                dtb = vmi->kpgd;
            }
            if (!dtb) {
                return 0;
            }
            start_addr = ctx->addr;
            break;
        case VMI_TM_PROCESS_DTB:
            if (!vmi->arch_interface) {
              return 0;
            }
            dtb = ctx->dtb;
            start_addr = ctx->addr;
            break;
        default:
            errprint("%s error: translation mechanism is not defined.\n", __FUNCTION__);
            return 0;
    }


    while (count > 0) {
        size_t read_len = 0;

        if(dtb) {
            if (VMI_SUCCESS != vmi_pagetable_lookup_cache(vmi, dtb, start_addr + buf_offset, &paddr)) {
                return buf_offset;
            }
        } else {
            paddr = start_addr + buf_offset;
        }


        /* access the memory */
        pfn = paddr >> vmi->page_shift;
        offset = (vmi->page_size - 1) & paddr;
        memory = vmi_read_page(vmi, pfn);
        if (NULL == memory) {
            return buf_offset;
        }

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

    return buf_offset;
}


// Reads memory at a guest's physical address
size_t
vmi_read_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    size_t count)
{
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_NONE,
        .addr = paddr
    };

    return vmi_read(vmi, &ctx, buf, count);
}

size_t
vmi_read_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    void *buf,
    size_t count)
{
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = vaddr,
        .pid = pid
    };

    return vmi_read(vmi, &ctx, buf, count);
}

size_t
vmi_read_ksym(
    vmi_instance_t vmi,
    char *sym,
    void *buf,
    size_t count)
{
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_KERNEL_SYMBOL,
        .ksym = sym,
    };

    return vmi_read(vmi, &ctx, buf, count);
}

///////////////////////////////////////////////////////////
// Easy access to memory
static inline status_t
vmi_read_X(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    void *value,
    size_t size)
{
    size_t len_read = vmi_read(vmi, ctx, value, size);

    if (len_read == size) {
        return VMI_SUCCESS;
    } else {
        return VMI_FAILURE;
    }
}

status_t
vmi_read_8(vmi_instance_t vmi,
    const access_context_t *ctx,
    uint8_t * value)
{
    return vmi_read_X(vmi, ctx, value, 1);
}

status_t
vmi_read_16(vmi_instance_t vmi,
    const access_context_t *ctx,
    uint16_t * value)
{
    return vmi_read_X(vmi, ctx, value, 2);
}

status_t
vmi_read_32(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint32_t * value)
{
    return vmi_read_X(vmi, ctx, value, 4);
}

status_t
vmi_read_64(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint64_t * value)
{
    return vmi_read_X(vmi, ctx, value, 8);
}

status_t
vmi_read_addr(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t *value)
{
    status_t ret = VMI_FAILURE;

    switch (vmi->page_mode) {
        case VMI_PM_AARCH64:// intentional fall-through
        case VMI_PM_IA32E:
            ret = vmi_read_X(vmi, ctx, value, 8);
            break;
        case VMI_PM_AARCH32:// intentional fall-through
        case VMI_PM_LEGACY: // intentional fall-through
        case VMI_PM_PAE: {
            uint32_t tmp = 0;
            ret = vmi_read_X(vmi, ctx, &tmp, 4);
            *value = (uint64_t) tmp;
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

    switch (ctx->translate_mechanism) {
        case VMI_TM_NONE:
            addr = ctx->addr;
            break;
        case VMI_TM_KERNEL_SYMBOL:
            if (!vmi->arch_interface || !vmi->os_interface || !vmi->kpgd)
              return 0;

            dtb = vmi->kpgd;
            addr = vmi_translate_ksym2v(vmi, ctx->ksym);
            break;
        case VMI_TM_PROCESS_PID:
            if(ctx->pid) {
                dtb = vmi_pid_to_dtb(vmi, ctx->pid);
            } else {
                dtb = vmi->kpgd;
            }
            if (!dtb) {
                return 0;
            }
            addr = ctx->addr;
            break;
        case VMI_TM_PROCESS_DTB:
            dtb = ctx->dtb;
            addr = ctx->addr;
            break;
        default:
            errprint("%s error: translation mechanism is not defined.\n", __FUNCTION__);
            return 0;
    }

    while (read_more) {

        addr += len;
        if(dtb) {
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
    if (vmi->os_interface && vmi->os_interface->os_read_unicode_struct)
        return vmi->os_interface->os_read_unicode_struct(vmi, ctx);

    return NULL;
}

///////////////////////////////////////////////////////////
// Easy access to physical memory
static inline status_t
vmi_read_X_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    void *value,
    size_t size)
{
    size_t len_read = vmi_read_pa(vmi, paddr, value, size);

    if (len_read == size) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

status_t
vmi_read_8_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint8_t * value)
{
    return vmi_read_X_pa(vmi, paddr, value, 1);
}

status_t
vmi_read_16_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint16_t * value)
{
    return vmi_read_X_pa(vmi, paddr, value, 2);
}

status_t
vmi_read_32_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t * value)
{
    return vmi_read_X_pa(vmi, paddr, value, 4);
}

status_t
vmi_read_64_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint64_t * value)
{
    return vmi_read_X_pa(vmi, paddr, value, 8);
}

status_t
vmi_read_addr_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    addr_t *value)
{
    status_t ret = VMI_FAILURE;

    switch(vmi->page_mode) {
        case VMI_PM_AARCH64:// intentional fall-through
        case VMI_PM_IA32E:
            ret = vmi_read_X_pa(vmi, paddr, value, 8);
            break;
        case VMI_PM_AARCH32:// intentional fall-through
        case VMI_PM_LEGACY: // intentional fall-through
        case VMI_PM_PAE: {
            uint32_t tmp = 0;
            ret = vmi_read_X_pa(vmi, paddr, &tmp, 4);
            *value = (uint64_t) tmp;
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
static inline status_t
vmi_read_X_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    void *value,
    size_t size)
{
    size_t len_read = vmi_read_va(vmi, vaddr, pid, value, size);

    if (len_read == size) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

status_t
vmi_read_8_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint8_t * value)
{
    return vmi_read_X_va(vmi, vaddr, pid, value, 1);
}

status_t
vmi_read_16_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint16_t * value)
{
    return vmi_read_X_va(vmi, vaddr, pid, value, 2);
}

status_t
vmi_read_32_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint32_t * value)
{
    return vmi_read_X_va(vmi, vaddr, pid, value, 4);
}

status_t
vmi_read_64_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint64_t * value)
{
    return vmi_read_X_va(vmi, vaddr, pid, value, 8);
}

status_t
vmi_read_addr_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    addr_t *value)
{
    status_t ret = VMI_FAILURE;

    switch(vmi->page_mode) {
        case VMI_PM_AARCH64:// intentional fall-through
        case VMI_PM_IA32E:
            ret = vmi_read_X_va(vmi, vaddr, pid, value, 8);
            break;
        case VMI_PM_AARCH32:// intentional fall-through
        case VMI_PM_LEGACY: // intentional fall-through
        case VMI_PM_PAE: {
            uint32_t tmp = 0;
            ret = vmi_read_X_va(vmi, vaddr, pid, &tmp, 4);
            *value = (uint64_t) tmp;
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
vmi_read_unicode_str_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid) {
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = vaddr,
        .pid = pid
    };

    return vmi_read_unicode_str(vmi, &ctx);
}

///////////////////////////////////////////////////////////
// Easy access to memory using kernel symbols
static status_t
vmi_read_X_ksym(
    vmi_instance_t vmi,
    char *sym,
    void *value,
    size_t size)
{
    size_t len_read = vmi_read_ksym(vmi, sym, value, size);

    if (len_read == size) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

status_t
vmi_read_8_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint8_t * value)
{
    return vmi_read_X_ksym(vmi, sym, value, 1);
}

status_t
vmi_read_16_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint16_t * value)
{
    return vmi_read_X_ksym(vmi, sym, value, 2);
}

status_t
vmi_read_32_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint32_t * value)
{
    return vmi_read_X_ksym(vmi, sym, value, 4);
}

status_t
vmi_read_64_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint64_t * value)
{
    return vmi_read_X_ksym(vmi, sym, value, 8);
}

status_t
vmi_read_addr_ksym(
    vmi_instance_t vmi,
    char *sym,
    addr_t *value)
{
    status_t ret = VMI_FAILURE;

    switch(vmi->page_mode) {
        case VMI_PM_AARCH64:// intentional fall-through
        case VMI_PM_IA32E:
            ret = vmi_read_X_ksym(vmi, sym, value, 8);
            break;
        case VMI_PM_AARCH32:// intentional fall-through
        case VMI_PM_LEGACY: // intentional fall-through
        case VMI_PM_PAE: {
            uint32_t tmp = 0;
            ret = vmi_read_X_ksym(vmi, sym, &tmp, 4);
            *value = (uint64_t) tmp;
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
    addr_t vaddr = vmi_translate_ksym2v(vmi, sym);

    return vmi_read_str_va(vmi, vaddr, 0);
}

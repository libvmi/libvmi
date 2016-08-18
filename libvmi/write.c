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

#include "private.h"
#include "driver/driver_wrapper.h"

///////////////////////////////////////////////////////////
// Classic write functions for access to memory
size_t
vmi_write(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    void *buf,
    size_t count)
{
    addr_t start_addr = 0;
    addr_t dtb = 0;
    addr_t paddr = 0;
    addr_t pfn = 0;
    addr_t offset = 0;
    size_t buf_offset = 0;

    if (NULL == buf) {
        dbprint(VMI_DEBUG_WRITE, "--%s: buf passed as NULL, returning without write\n",
                __FUNCTION__);
        return 0;
    }

    if (NULL == ctx) {
        dbprint(VMI_DEBUG_WRITE, "--%s: ctx passed as NULL, returning without write\n",
                __FUNCTION__);
        return 0;
    }

    switch (ctx->translate_mechanism) {
        case VMI_TM_NONE:
            start_addr = ctx->addr;
            break;
        case VMI_TM_KERNEL_SYMBOL:
            if (!vmi->arch_interface || !vmi->os_interface) {
              return 0;
            }
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
        size_t write_len = 0;

        if(dtb) {
            if (VMI_SUCCESS != vmi_pagetable_lookup_cache(vmi, dtb, start_addr + buf_offset, &paddr)) {
                return buf_offset;
            }
        } else {
            paddr = start_addr + buf_offset;
        }

        /* determine how much we can write to this page */
        offset = (vmi->page_size - 1) & paddr;
        if ((offset + count) > vmi->page_size) {
            write_len = vmi->page_size - offset;
        }
        else {
            write_len = count;
        }

        /* do the write */
        if (VMI_FAILURE ==
            driver_write(vmi, paddr,
                         ((char *) buf + (addr_t) buf_offset),
                         write_len)) {
            return buf_offset;
        }

        /* set variables for next loop */
        count -= write_len;
        buf_offset += write_len;
    }

    return buf_offset;
}

size_t
vmi_write_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    size_t count)
{
    if (NULL == buf) {
        dbprint(VMI_DEBUG_WRITE, "--%s: buf passed as NULL, returning without write\n",
                __FUNCTION__);
        return 0;
    }
    if (VMI_SUCCESS == driver_write(vmi, paddr, buf, count)) {
        return count;
    }
    else {
        return 0;
    }
}

size_t
vmi_write_va(
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
    return vmi_write(vmi, &ctx, buf, count);
}

size_t
vmi_write_ksym(
    vmi_instance_t vmi,
    char *sym,
    void *buf,
    size_t count)
{
    addr_t vaddr = vmi_translate_ksym2v(vmi, sym);

    return vmi_write_va(vmi, vaddr, 0, buf, count);
}

///////////////////////////////////////////////////////////
// Easy write to memory
static inline
status_t vmi_write_X(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    void *value,
    int size)
{
    size_t len_write = vmi_write(vmi, ctx, value, size);

    if (len_write == size) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

status_t
vmi_write_8(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint8_t * value)
{
    return vmi_write_X(vmi, ctx, value, 1);
}

status_t
vmi_write_16(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint16_t * value)
{
    return vmi_write_X(vmi, ctx, value, 2);
}

status_t
vmi_write_32(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint32_t * value)
{
    return vmi_write_X(vmi, ctx, value, 4);
}

status_t
vmi_write_64(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint64_t * value)
{
    return vmi_write_X(vmi, ctx, value, 8);
}

status_t
vmi_write_addr(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t * value)
{
    switch(vmi->page_mode) {
        case VMI_PM_IA32E:
            return vmi_write_X(vmi, ctx, value, 8);
        case VMI_PM_AARCH32:// intentional fall-through
        case VMI_PM_LEGACY: // intentional fall-through
        case VMI_PM_PAE:
            return vmi_write_X(vmi, ctx, value, 4);
        default:
            dbprint(VMI_DEBUG_WRITE,
                "--%s: unknown page mode, can't write addr as pointer width is unknown\n",
                __FUNCTION__);
            break;
    }

    return VMI_FAILURE;
}

///////////////////////////////////////////////////////////
// Easy write to physical memory
static status_t
vmi_write_X_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    void *value,
    int size)
{
    size_t len_write = vmi_write_pa(vmi, paddr, value, size);

    if (len_write == size) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

status_t
vmi_write_8_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint8_t * value)
{
    return vmi_write_X_pa(vmi, paddr, value, 1);
}

status_t
vmi_write_16_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint16_t * value)
{
    return vmi_write_X_pa(vmi, paddr, value, 2);
}

status_t
vmi_write_32_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t * value)
{
    return vmi_write_X_pa(vmi, paddr, value, 4);
}

status_t
vmi_write_64_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint64_t * value)
{
    return vmi_write_X_pa(vmi, paddr, value, 8);
}

status_t
vmi_write_addr_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    addr_t * value)
{
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_NONE,
        .addr = paddr
    };

    return vmi_write_addr(vmi, &ctx, value);
}

///////////////////////////////////////////////////////////
// Easy write to virtual memory
static status_t
vmi_write_X_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    void *value,
    int size)
{
    size_t len_write = vmi_write_va(vmi, vaddr, pid, value, size);

    if (len_write == size) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

status_t
vmi_write_8_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint8_t * value)
{
    return vmi_write_X_va(vmi, vaddr, pid, value, 1);
}

status_t
vmi_write_16_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint16_t * value)
{
    return vmi_write_X_va(vmi, vaddr, pid, value, 2);
}

status_t
vmi_write_32_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint32_t * value)
{
    return vmi_write_X_va(vmi, vaddr, pid, value, 4);
}

status_t
vmi_write_64_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint64_t * value)
{
    return vmi_write_X_va(vmi, vaddr, pid, value, 8);
}

status_t
vmi_write_addr_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    addr_t * value)
{
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = vaddr,
        .pid = pid
    };
    return vmi_write_addr(vmi, &ctx, value);
}

///////////////////////////////////////////////////////////
// Easy write to memory using kernel symbols
static status_t
vmi_write_X_ksym(
    vmi_instance_t vmi,
    char *sym,
    void *value,
    int size)
{
    size_t len_write = vmi_write_ksym(vmi, sym, value, size);

    if (len_write == size) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

status_t
vmi_write_8_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint8_t * value)
{
    return vmi_write_X_ksym(vmi, sym, value, 1);
}

status_t
vmi_write_16_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint16_t * value)
{
    return vmi_write_X_ksym(vmi, sym, value, 2);
}

status_t
vmi_write_32_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint32_t * value)
{
    return vmi_write_X_ksym(vmi, sym, value, 4);
}

status_t
vmi_write_64_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint64_t * value)
{
    return vmi_write_X_ksym(vmi, sym, value, 8);
}

status_t
vmi_write_addr_ksym(
    vmi_instance_t vmi,
    char *sym,
    addr_t * value)
{
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_KERNEL_SYMBOL,
        .ksym = sym
    };

    return vmi_write_addr(vmi, &ctx, value);
}


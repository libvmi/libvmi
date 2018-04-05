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
status_t
vmi_write(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t count,
    void *buf,
    size_t *bytes_written)
{
    status_t ret = VMI_FAILURE;
    addr_t start_addr = 0;
    addr_t dtb = 0;
    addr_t paddr = 0;
    addr_t offset = 0;
    size_t buf_offset = 0;

    if (NULL == vmi) {
        dbprint(VMI_DEBUG_WRITE, "--%s: vmi passed as NULL, returning without write\n",
                __FUNCTION__);
        goto done;
    }

    if (NULL == buf) {
        dbprint(VMI_DEBUG_WRITE, "--%s: buf passed as NULL, returning without write\n",
                __FUNCTION__);
        goto done;
    }

    if (NULL == ctx) {
        dbprint(VMI_DEBUG_WRITE, "--%s: ctx passed as NULL, returning without write\n",
                __FUNCTION__);
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

            if (!ctx->pid)
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
            return 0;
    }

    while (count > 0) {
        size_t write_len = 0;

        if (dtb) {
            if (VMI_SUCCESS != vmi_pagetable_lookup_cache(vmi, dtb, start_addr + buf_offset, &paddr))
                goto done;
        } else
            paddr = start_addr + buf_offset;

        /* determine how much we can write to this page */
        offset = (vmi->page_size - 1) & paddr;
        if ((offset + count) > vmi->page_size) {
            write_len = vmi->page_size - offset;
        } else {
            write_len = count;
        }

        /* do the write */
        if (VMI_FAILURE ==
                driver_write(vmi, paddr,
                             ((char *) buf + (addr_t) buf_offset),
                             write_len)) {
            goto done;
        }

        /* set variables for next loop */
        count -= write_len;
        buf_offset += write_len;
    }

    ret = VMI_SUCCESS;

done:
    if ( bytes_written )
        *bytes_written = buf_offset;

    return ret;
}

status_t
vmi_write_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    size_t count,
    void *buf,
    size_t *bytes_written)
{
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_NONE,
        .addr = paddr,
    };
    return vmi_write(vmi, &ctx, count, buf, bytes_written);
}

status_t
vmi_write_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    size_t count,
    void *buf,
    size_t *bytes_written)
{
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = vaddr,
        .pid = pid
    };
    return vmi_write(vmi, &ctx, count, buf, bytes_written);
}

status_t
vmi_write_ksym(
    vmi_instance_t vmi,
    char *sym,
    size_t count,
    void *buf,
    size_t *bytes_written)
{
    addr_t vaddr = 0;
    if ( VMI_SUCCESS == vmi_translate_ksym2v(vmi, sym, &vaddr) )
        return vmi_write_va(vmi, vaddr, 0, count, buf, bytes_written);

    if ( bytes_written )
        *bytes_written = 0;

    return VMI_FAILURE;
}

///////////////////////////////////////////////////////////
// Easy write to memory
status_t
vmi_write_8(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint8_t * value)
{
    return vmi_write(vmi, ctx, 1, value, NULL);
}

status_t
vmi_write_16(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint16_t * value)
{
    return vmi_write(vmi, ctx, 2, value, NULL);
}

status_t
vmi_write_32(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint32_t * value)
{
    return vmi_write(vmi, ctx, 4, value, NULL);
}

status_t
vmi_write_64(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint64_t * value)
{
    return vmi_write(vmi, ctx, 8, value, NULL);
}

status_t
vmi_write_addr(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t * value)
{
    if (!vmi) {
        dbprint(VMI_DEBUG_WRITE, "--%s: vmi passed as NULL, returning without write\n",
                __FUNCTION__);
        return VMI_FAILURE;
    }

    switch (vmi->page_mode) {
        case VMI_PM_AARCH64:// intentional fall-through
        case VMI_PM_IA32E:
            return vmi_write(vmi, ctx, 8, value, NULL);
        case VMI_PM_AARCH32:// intentional fall-through
        case VMI_PM_LEGACY: // intentional fall-through
        case VMI_PM_PAE:
            return vmi_write(vmi, ctx, 4, value, NULL);
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
status_t
vmi_write_8_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint8_t * value)
{
    return vmi_write_pa(vmi, paddr, 1, value, NULL);
}

status_t
vmi_write_16_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint16_t * value)
{
    return vmi_write_pa(vmi, paddr, 2, value, NULL);
}

status_t
vmi_write_32_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t * value)
{
    return vmi_write_pa(vmi, paddr, 4, value, NULL);
}

status_t
vmi_write_64_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint64_t * value)
{
    return vmi_write_pa(vmi, paddr, 8, value, NULL);
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
status_t
vmi_write_8_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint8_t * value)
{
    return vmi_write_va(vmi, vaddr, pid, 1, value, NULL);
}

status_t
vmi_write_16_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint16_t * value)
{
    return vmi_write_va(vmi, vaddr, pid, 2, value, NULL);
}

status_t
vmi_write_32_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint32_t * value)
{
    return vmi_write_va(vmi, vaddr, pid, 4, value, NULL);
}

status_t
vmi_write_64_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint64_t * value)
{
    return vmi_write_va(vmi, vaddr, pid, 8, value, NULL);
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
status_t
vmi_write_8_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint8_t * value)
{
    return vmi_write_ksym(vmi, sym, 1, value, NULL);
}

status_t
vmi_write_16_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint16_t * value)
{
    return vmi_write_ksym(vmi, sym, 2, value, NULL);
}

status_t
vmi_write_32_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint32_t * value)
{
    return vmi_write_ksym(vmi, sym, 4, value, NULL);
}

status_t
vmi_write_64_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint64_t * value)
{
    return vmi_write_ksym(vmi, sym, 8, value, NULL);
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

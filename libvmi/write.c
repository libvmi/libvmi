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

///////////////////////////////////////////////////////////
// Classic write functions for access to memory

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
    addr_t paddr = 0;
    addr_t pfn = 0;
    addr_t offset = 0;
    size_t buf_offset = 0;
    process_context_t *ctx = (process_context_t *)&pid;

    if (NULL == buf) {
        dbprint(VMI_DEBUG_WRITE, "--%s: buf passed as NULL, returning without write\n",
                __FUNCTION__);
        return 0;
    }

    while (count > 0) {
        size_t write_len = 0;

        if (!ctx->pid) {
            paddr = vmi_translate_kv2p(vmi, vaddr + buf_offset);
        } else if (ctx->pid > 0) {
            paddr = vmi_translate_uv2p(vmi, vaddr + buf_offset, pid);
        } else {
            paddr = vmi_pagetable_lookup(vmi, vaddr, ctx->dtb);
        }

        if (!paddr) {
            return buf_offset;
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

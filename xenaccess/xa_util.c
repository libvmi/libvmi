/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2007  Bryan D. Payne (bryan@thepaynes.cc)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * --------------------
 * This file contains functions that are generally useful for use
 * throughout the rest of the library.
 *
 * File: xa_util.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 *
 * $Id: xa_template 36 2006-11-30 01:38:20Z bdpayne $
 * $Date: 2006-11-29 20:38:20 -0500 (Wed, 29 Nov 2006) $
 */

#include "xenaccess.h"
#include "xa_private.h"
#include <string.h>
#include <stdarg.h>

int xa_read_long_mach (
        xa_instance_t *instance, uint32_t maddr, uint32_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = xa_access_ma(instance, maddr, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint32_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return XA_SUCCESS;
    }
    else{
        return XA_FAILURE;
    }
}

int xa_read_long_long_mach (
        xa_instance_t *instance, uint32_t maddr, uint64_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = xa_access_ma(instance, maddr, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint64_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return XA_SUCCESS;
    }
    else{
        return XA_FAILURE;
    }
}

int xa_read_long_phys (
        xa_instance_t *instance, uint32_t paddr, uint32_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = xa_access_pa(instance, paddr, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint32_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return XA_SUCCESS;
    }
    else{
        return XA_FAILURE;
    }
}

int xa_read_long_long_phys (
        xa_instance_t *instance, uint32_t paddr, uint64_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = xa_access_pa(instance, paddr, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint64_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return XA_SUCCESS;
    }
    else{
        return XA_FAILURE;
    }
}

int xa_read_long_virt (
        xa_instance_t *instance, uint32_t vaddr, int pid, uint32_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = xa_access_user_va(instance, vaddr, &offset, pid, PROT_READ);
    if (NULL != memory){
        *value = *((uint32_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return XA_SUCCESS;
    }
    else{
        return XA_FAILURE;
    }
}

int xa_read_long_long_virt (
        xa_instance_t *instance, uint32_t vaddr, int pid, uint64_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = xa_access_user_va(instance, vaddr, &offset, pid, PROT_READ);
    if (NULL != memory){
        *value = *((uint64_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return XA_SUCCESS;
    }
    else{
        return XA_FAILURE;
    }
}

int xa_read_long_sym (
        xa_instance_t *instance, char *sym, uint32_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = xa_access_kernel_sym(instance, sym, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint32_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return XA_SUCCESS;
    }
    else{
        return XA_FAILURE;
    }
}

int xa_read_long_long_sym (
        xa_instance_t *instance, char *sym, uint64_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = xa_access_kernel_sym(instance, sym, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint64_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return XA_SUCCESS;
    }
    else{
        return XA_FAILURE;
    }
}

int xa_symbol_to_address (xa_instance_t *instance, char *sym, uint32_t *vaddr)
{
    if (XA_OS_LINUX == instance->os_type){
       return linux_system_map_symbol_to_address(instance, sym, vaddr);
    }
    else if (XA_OS_WINDOWS == instance->os_type){
        return windows_symbol_to_address(instance, sym, vaddr);
    }
    else{
        return XA_FAILURE;
    }
}

int xa_get_bit (unsigned long reg, int bit)
{
    unsigned long mask = 1 << bit;
    if (reg & mask){
        return 1;
    }
    else{
        return 0;
    }
}

void *xa_map_page (xa_instance_t *instance, int prot, unsigned long frame_num)
{
    void *memory = NULL;

    if (XA_MODE_XEN == instance->mode){
#ifdef ENABLE_XEN
        memory = xc_map_foreign_range(
            instance->m.xen.xc_handle,
            instance->m.xen.domain_id,
            1,
            prot,
            frame_num);
#endif /* ENABLE_XEN */
    }
    else if (XA_MODE_FILE == instance->mode){
        memory = xa_map_file_range(instance, prot, frame_num);
    }
    else{
        xa_dbprint("BUG: invalid mode\n");
    }

    return memory;
}

/* This function is taken from Markus Armbruster's
 * xc_map_foreign_pages that is now part of xc_util.c.
 * 
 * It is a very nice function that unfortunately
 * only appears in very recent libxc's (late 2007).
 * 
 * Calls to this function should be replaced with
 * the libxc equivalent when Xen 3.1.2 becomes widely
 * distributed.
 */
#ifdef ENABLE_XEN
#ifndef HAVE_MAP_FOREIGN
void *xc_map_foreign_pages(int xc_handle, uint32_t dom, int prot,
                           const xen_pfn_t *arr, int num)
{
    xen_pfn_t *pfn;
    void *res;
    int i;

    pfn = malloc(num * sizeof(*pfn));
    if (!pfn)
        return NULL;
    memcpy(pfn, arr, num * sizeof(*pfn));

    res = xc_map_foreign_batch(xc_handle, dom, prot, pfn, num);
    if (res) {
        for (i = 0; i < num; i++) {
            if ((pfn[i] & 0xF0000000UL) == 0xF0000000UL) {
                /*
                 * xc_map_foreign_batch() doesn't give us an error
                 * code, so we have to make one up.  May not be the
                 * appropriate one.
                 */
                errno = EINVAL;
                munmap(res, num * PAGE_SIZE);
                res = NULL;
                break;
            }
        }
    }

    free(pfn);
    return res;
}
#endif /* HAVE_MAP_FOREIGN */
#endif /* ENABLE_XEN */

#ifndef XA_DEBUG
/* Nothing */
#else
void xa_dbprint(char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}
#endif

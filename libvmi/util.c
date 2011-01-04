/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include "libvmi.h"
#include "private.h"
#include <string.h>
#include <stdarg.h>

status_t vmi_read_long_mach (
        vmi_instance_t instance, uint32_t maddr, uint32_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = vmi_access_ma(instance, maddr, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint32_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_read_long_long_mach (
        vmi_instance_t instance, uint32_t maddr, uint64_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = vmi_access_ma(instance, maddr, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint64_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_read_long_phys (
        vmi_instance_t instance, uint32_t paddr, uint32_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = vmi_access_pa(instance, paddr, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint32_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_read_long_long_phys (
        vmi_instance_t instance, uint32_t paddr, uint64_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = vmi_access_pa(instance, paddr, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint64_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_read_long_virt (
        vmi_instance_t instance, uint32_t vaddr, int pid, uint32_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = vmi_access_user_va(instance, vaddr, &offset, pid, PROT_READ);
    if (NULL != memory){
        *value = *((uint32_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_read_long_long_virt (
        vmi_instance_t instance, uint32_t vaddr, int pid, uint64_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = vmi_access_user_va(instance, vaddr, &offset, pid, PROT_READ);
    if (NULL != memory){
        *value = *((uint64_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_read_long_sym (
        vmi_instance_t instance, char *sym, uint32_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = vmi_access_kernel_sym(instance, sym, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint32_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_read_long_long_sym (
        vmi_instance_t instance, char *sym, uint64_t *value)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    memory = vmi_access_kernel_sym(instance, sym, &offset, PROT_READ);
    if (NULL != memory){
        *value = *((uint64_t*)(memory + offset));
        munmap(memory, instance->page_size);
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_symbol_to_address (vmi_instance_t instance, char *sym, uint32_t *vaddr)
{
    if (VMI_OS_LINUX == instance->os_type){
       return linux_system_map_symbol_to_address(instance, sym, vaddr);
    }
    else if (VMI_OS_WINDOWS == instance->os_type){
        return windows_symbol_to_address(instance, sym, vaddr);
    }
    else{
        return VMI_FAILURE;
    }
}

int vmi_get_bit (unsigned long reg, int bit)
{
    unsigned long mask = 1 << bit;
    if (reg & mask){
        return 1;
    }
    else{
        return 0;
    }
}

void *vmi_map_page (vmi_instance_t vmi, int prot, unsigned long frame_num)
{
    return driver_map_page(vmi, prot, frame_num);
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

    pfn = safe_malloc(num * sizeof(*pfn));
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


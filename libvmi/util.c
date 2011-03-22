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
#include "driver/interface.h"
#include <string.h>
#include <stdarg.h>
#include <sys/mman.h>

///////////////////////////////////////////////////////////
// Classic read functions for access to memory
size_t vmi_read_pa (vmi_instance_t vmi, uint32_t paddr, void *buf, size_t count)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    size_t buf_offset = 0;

    while (count > 0){
        size_t read_len = 0;

        /* access the memory */
        memory = vmi_access_pa(vmi, paddr + buf_offset, &offset, PROT_READ);
        if (NULL == memory){
            return buf_offset;
        }

        /* determine how much we can read */
        if ((offset + count) > vmi->page_size){
            read_len = vmi->page_size - offset;
        }
        else{
            read_len = count;
        }
        
        /* do the read */
        memcpy( ((char *) buf) + buf_offset, memory + offset, read_len);
        munmap(memory, vmi->page_size);

        /* set variables for next loop */
        count -= read_len;
        buf_offset += read_len;
    }

    return buf_offset;
}

size_t vmi_read_va (vmi_instance_t vmi, uint32_t vaddr, int pid, void *buf, size_t count)
{
    uint32_t paddr = 0;
    if (pid){
        paddr = vmi_translate_uv2p(vmi, vaddr, pid);
    }
    else{
        paddr = vmi_translate_kv2p(vmi, vaddr);
    }
    return vmi_read_pa(vmi, paddr, buf, count);
}

size_t vmi_read_ksym (vmi_instance_t vmi, char *symbol, void *buf, size_t count)
{
    uint32_t vaddr = vmi_translate_ksym2v(vmi, symbol);
    return vmi_read_va(vmi, vaddr, 0, buf, count);
}

///////////////////////////////////////////////////////////
// Easy access to machine memory

//TODO update the mach access functions throughout
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

///////////////////////////////////////////////////////////
// Easy access to physical memory
static status_t vmi_read_X_pa (vmi_instance_t vmi, uint32_t paddr, void *value, int size)
{
    size_t len_read = vmi_read_pa(vmi, paddr, value, size);
    if (len_read == size){
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_read_8_pa (vmi_instance_t vmi, uint32_t paddr, uint8_t *value)
{
    return vmi_read_X_pa(vmi, paddr, value, 1);
}

status_t vmi_read_16_pa (vmi_instance_t vmi, uint32_t paddr, uint16_t *value)
{
    return vmi_read_X_pa(vmi, paddr, value, 2);
}

status_t vmi_read_32_pa (vmi_instance_t vmi, uint32_t paddr, uint32_t *value)
{
    return vmi_read_X_pa(vmi, paddr, value, 4);
}

status_t vmi_read_64_pa (vmi_instance_t vmi, uint32_t paddr, uint64_t *value)
{
    return vmi_read_X_pa(vmi, paddr, value, 8);
}

///////////////////////////////////////////////////////////
// Easy access to virtual memory
static status_t vmi_read_X_va (vmi_instance_t vmi, uint32_t vaddr, int pid, void *value, int size)
{
    size_t len_read = vmi_read_va(vmi, vaddr, pid, value, size);
    if (len_read == size){
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_read_8_va (vmi_instance_t vmi, uint32_t vaddr, int pid, uint8_t *value)
{
    return vmi_read_X_va(vmi, vaddr, pid, value, 1);
}

status_t vmi_read_16_va (vmi_instance_t vmi, uint32_t vaddr, int pid, uint16_t *value)
{
    return vmi_read_X_va(vmi, vaddr, pid, value, 2);
}

status_t vmi_read_32_va (vmi_instance_t vmi, uint32_t vaddr, int pid, uint32_t *value)
{
    return vmi_read_X_va(vmi, vaddr, pid, value, 4);
}

status_t vmi_read_64_va (vmi_instance_t vmi, uint32_t vaddr, int pid, uint64_t *value)
{
    return vmi_read_X_va(vmi, vaddr, pid, value, 8);
}

///////////////////////////////////////////////////////////
// Easy access to memory using kernel symbols
static status_t vmi_read_X_ksym (vmi_instance_t vmi, char *sym, void *value, int size)
{
    size_t len_read = vmi_read_ksym(vmi, sym, value, size);
    if (len_read == size){
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_read_8_ksym (vmi_instance_t vmi, char *sym, uint8_t *value)
{
    return vmi_read_X_ksym(vmi, sym, value, 1);
}

status_t vmi_read_16_ksym (vmi_instance_t vmi, char *sym, uint16_t *value)
{
    return vmi_read_X_ksym(vmi, sym, value, 2);
}

status_t vmi_read_32_ksym (vmi_instance_t vmi, char *sym, uint32_t *value)
{
    return vmi_read_X_ksym(vmi, sym, value, 4);
}

status_t vmi_read_64_ksym (vmi_instance_t vmi, char *sym, uint64_t *value)
{
    return vmi_read_X_ksym(vmi, sym, value, 8);
}

///////////////////////////////////////////////////////////
// Other utility functions
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
#if ENABLE_XEN == 1
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


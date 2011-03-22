/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include "private.h"
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

status_t windows_symbol_to_address (
        vmi_instance_t vmi, char *symbol, uint32_t *address)
{
    /* see if we have a cr3 value */
    reg_t cr3 = 0;
    driver_get_vcpureg(vmi, &cr3, CR3, 0);

    /* check kpcr if we have a cr3 */
    if (cr3 && VMI_SUCCESS == windows_kpcr_lookup(vmi, symbol, address)){
        dbprint("--got symbol from kpcr (%s --> 0x%lx).\n", symbol, *address);
        return VMI_SUCCESS;
    }

    /* check exports */
    else if (VMI_SUCCESS == windows_export_to_rva(vmi, symbol, address)){
        uint32_t rva = *address;
        uint32_t phys_address = vmi->os.windows_instance.ntoskrnl + rva;
        *address = phys_address + vmi->page_offset;
        dbprint("--got symbol from PE export table (%s --> 0x%lx).\n", symbol, *address);
        return VMI_SUCCESS;
    }

    /*TODO check symbol server ??? */

    return VMI_FAILURE;
}

/* find the ntoskrnl base address */
#define NUM_BASE_ADDRESSES 11
uint32_t get_ntoskrnl_base (vmi_instance_t vmi)
{
    uint32_t paddr;
    uint32_t sysproc_rva;
    int i = 0;

    /* Various base addresses that are known to exist across different
       versions of windows.  If you add to this list, be sure to change
       the value of NUM_BASE_ADDRESSES as well! */
    uint32_t base_address[NUM_BASE_ADDRESSES] = {
        0x00100000, /* NT 4 */
        0x00400000, /* Windows 2000 */
        0x004d4000, /* Windows XP */
        0x004d0000, /* Windows XP */
        0x004d5000, /* Windows XP */
        0x00a02000, /* Windows XP */
        0x00496000, /* Windows XP */
        0x004d7000, /* Windows XP SP2/SP3 */
        0x004de000, /* Windows Server 2003 */
        0x00800000, /* Windows Server 2003 SP1 */
        0x01800000  /* Windows Vista */
    };

    /* start by looking at known base addresses */
    for (i = 0; i < NUM_BASE_ADDRESSES; ++i){
        paddr = base_address[i];
        if (valid_ntoskrnl_start(vmi, paddr) == VMI_SUCCESS){
            goto fast_exit;
        }
    }

    /* start the downward search looking for MZ header */
    fprintf(stderr, "Note: Fast checking for kernel base address failed, XenAccess\n");
    fprintf(stderr, "is searching for the correct address.\n");
    paddr = 0x0 + vmi->page_size;
    while (1){
        if (valid_ntoskrnl_start(vmi, paddr) == VMI_SUCCESS){
            goto fast_exit;
        }

        paddr += vmi->page_size;
        if (paddr <= 0 || 0x40000000 <= paddr){
            dbprint("--get_ntoskrnl_base failed\n");
            return 0;
        }
    }

fast_exit:
    return paddr;
}

void *windows_access_kernel_symbol (
        vmi_instance_t vmi, char *symbol, uint32_t *offset, int prot)
{
    uint32_t virt_address;
    uint32_t address;

    /* check the LRU cache */
    if (vmi_check_cache_sym(vmi, symbol, 0, &address)){
        return vmi_access_ma(vmi, address, offset, prot);
    }

    /* get the VA of the symbol */
    if (VMI_FAILURE == windows_symbol_to_address(vmi, symbol, &virt_address)){
        dbprint("--failed to lookup address for '%s'\n", symbol);
        return NULL;
    }

    vmi_update_cache(vmi, symbol, virt_address, 0, 0);
    return vmi_access_pa(vmi, virt_address - vmi->page_offset, offset, prot);
}

/* finds the EPROCESS struct for a given pid */
unsigned char *windows_get_EPROCESS (
        vmi_instance_t vmi, int pid, uint32_t *offset)
{
    unsigned char *memory = NULL;
    uint32_t list_head = 0, next_process = 0;
    int task_pid = 0;
    int pid_offset = vmi->os.windows_instance.pid_offset;
    int tasks_offset = vmi->os.windows_instance.tasks_offset;

    /* first we need a pointer to this pid's EPROCESS struct */
    next_process = vmi->init_task;
    list_head = next_process;

    while (1){
        memory = vmi_access_kernel_va(vmi, next_process, offset, PROT_READ);
        if (NULL == memory){
            errprint("Failed to get EPROCESS list next pointer.\n");
            goto error_exit;
        }
        memcpy(&next_process, memory + *offset, 4);

        /* if we are back at the list head, we are done */
        if (list_head == next_process){
            goto error_exit;
        }

        memcpy(&task_pid,
               memory + *offset + pid_offset - tasks_offset,
               4
        );

        /* if pid matches, then we found what we want */
        if (task_pid == pid){
            return memory;
        }
        munmap(memory, vmi->page_size);
    }

error_exit:
    if (memory) munmap(memory, vmi->page_size);
    return NULL;
}

/* finds the address of the page global directory for a given pid */
uint32_t windows_pid_to_pgd (vmi_instance_t vmi, int pid)
{
    unsigned char *memory = NULL;
    uint32_t pgd = 0, ptr = 0, offset = 0;
    int pdbase_offset = vmi->os.windows_instance.pdbase_offset;
    int tasks_offset = vmi->os.windows_instance.tasks_offset;

    /* first we need a pointer to this pid's EPROCESS struct */
    memory = windows_get_EPROCESS(vmi, pid, &offset);
    if (NULL == memory){
        errprint("Could not find EPROCESS struct for pid = %d.\n", pid);
        goto error_exit;
    }

    /* now follow the pointer to the memory descriptor and
       grab the pgd value */
    pgd = *((uint32_t*)(memory + offset + pdbase_offset - tasks_offset));
    munmap(memory, vmi->page_size);

    /* update the cache with this new pid->pgd mapping */
    vmi_update_pid_cache(vmi, pid, pgd);

error_exit:
    if (memory) munmap(memory, vmi->page_size);
    return pgd;
}

/* fills the taskaddr struct for a given windows process */
status_t vmi_windows_get_peb (
        vmi_instance_t vmi, int pid, vmi_windows_peb_t *peb)
{
    unsigned char *memory;
    uint32_t ptr = 0, offset = 0;
    int peb_offset = vmi->os.windows_instance.peb_offset;
    int tasks_offset = vmi->os.windows_instance.tasks_offset;
    int iba_offset = vmi->os.windows_instance.iba_offset;
    int ph_offset = vmi->os.windows_instance.ph_offset;

    /* find the right EPROCESS struct */
    memory = windows_get_EPROCESS(vmi, pid, &offset);
    if (NULL == memory){
        errprint("Could not find EPROCESS struct for pid = %d.\n", pid);
        goto error_exit;
    }
    ptr = *((uint32_t*)(memory+offset + peb_offset - tasks_offset));
    munmap(memory, vmi->page_size);

    /* copy appropriate values into peb struct */
    vmi_read_32_va(vmi, ptr + iba_offset, pid, &(peb->ImageBaseAddress));
    vmi_read_32_va(vmi, ptr + ph_offset, pid, &(peb->ProcessHeap));

    return VMI_SUCCESS;

error_exit:
    if (memory) munmap(memory, vmi->page_size);
    return VMI_FAILURE;
}

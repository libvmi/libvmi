/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2008  Bryan D. Payne (bryan@thepaynes.cc)
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
 * This file contains functions for accessing memory data in Windows.
 *
 * File: windows_memory.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "xa_private.h"

int windows_symbol_to_address (
        xa_instance_t *instance, char *symbol, uint32_t *address)
{
    /* check exports first */
    return windows_export_to_rva(instance, symbol, address);

    /*TODO check symbol server */
}

/* find the ntoskrnl base address */
#define NUM_BASE_ADDRESSES 11
uint32_t get_ntoskrnl_base (xa_instance_t *instance)
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
        if (valid_ntoskrnl_start(instance, paddr) == XA_SUCCESS){
            goto fast_exit;
        }
    }

    /* start the downward search looking for MZ header */
    fprintf(stderr, "Note: Fast checking for kernel base address failed, XenAccess\n");
    fprintf(stderr, "is searching for the correct address.\n");
    paddr = 0x0 + instance->page_size;
    while (1){
        if (valid_ntoskrnl_start(instance, paddr) == XA_SUCCESS){
            goto fast_exit;
        }

        paddr += instance->page_size;
        if (paddr <= 0 || 0x40000000 <= paddr){
            xa_dbprint("--get_ntoskrnl_base failed\n");
            return 0;
        }
    }

fast_exit:
    return paddr;
}

void *windows_access_kernel_symbol (
        xa_instance_t *instance, char *symbol, uint32_t *offset, int prot)
{
    uint32_t virt_address;
    uint32_t phys_address;
    uint32_t address;
    uint32_t rva;

    /* check the LRU cache */
    if (xa_check_cache_sym(instance, symbol, 0, &address)){
        return xa_access_ma(instance, address, offset, PROT_READ);
    }

    /* get the RVA of the symbol */
    if (windows_symbol_to_address(instance, symbol, &rva) == XA_FAILURE){
        return NULL;
    }

    /* convert RVA into virt address */
    phys_address = instance->os.windows_instance.ntoskrnl + rva;
    virt_address = phys_address + instance->page_offset;

    xa_update_cache(instance, symbol, virt_address, 0, 0);
    return xa_access_pa(instance, phys_address, offset, prot);
}

/* finds the EPROCESS struct for a given pid */
unsigned char *windows_get_EPROCESS (
        xa_instance_t *instance, int pid, uint32_t *offset)
{
    unsigned char *memory = NULL;
    uint32_t list_head = 0, next_process = 0;
    int task_pid = 0;
    int pid_offset = instance->os.windows_instance.pid_offset;
    int tasks_offset = instance->os.windows_instance.tasks_offset;

    /* first we need a pointer to this pid's EPROCESS struct */
    next_process = instance->init_task;
    list_head = next_process;

    while (1){
        memory = xa_access_kernel_va(instance, next_process, offset, PROT_READ);
        if (NULL == memory){
            fprintf(stderr, "ERROR: failed to get EPROCESS list next pointer");
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
        munmap(memory, instance->page_size);
    }

error_exit:
    if (memory) munmap(memory, instance->page_size);
    return NULL;
}

/* finds the address of the page global directory for a given pid */
uint32_t windows_pid_to_pgd (xa_instance_t *instance, int pid)
{
    unsigned char *memory = NULL;
    uint32_t pgd = 0, ptr = 0, offset = 0;
    int pdbase_offset = instance->os.windows_instance.pdbase_offset;
    int tasks_offset = instance->os.windows_instance.tasks_offset;

    /* first we need a pointer to this pid's EPROCESS struct */
    memory = windows_get_EPROCESS(instance, pid, &offset);
    if (NULL == memory){
        fprintf(stderr, "ERROR: could not find EPROCESS struct for pid = %d\n", pid);
        goto error_exit;
    }

    /* now follow the pointer to the memory descriptor and
       grab the pgd value */
    pgd = *((uint32_t*)(memory + offset + pdbase_offset - tasks_offset));
    munmap(memory, instance->page_size);

    /* update the cache with this new pid->pgd mapping */
    xa_update_pid_cache(instance, pid, pgd);

error_exit:
    if (memory) munmap(memory, instance->page_size);
    return pgd;
}

/* fills the taskaddr struct for a given windows process */
int xa_windows_get_peb (
        xa_instance_t *instance, int pid, xa_windows_peb_t *peb)
{
    unsigned char *memory;
    uint32_t ptr = 0, offset = 0;
    int peb_offset = instance->os.windows_instance.peb_offset;
    int tasks_offset = instance->os.windows_instance.tasks_offset;
    int iba_offset = instance->os.windows_instance.iba_offset;
    int ph_offset = instance->os.windows_instance.ph_offset;

    /* find the right EPROCESS struct */
    memory = windows_get_EPROCESS(instance, pid, &offset);
    if (NULL == memory){
        fprintf(stderr, "ERROR: could not find EPROCESS struct for pid = %d\n", pid);
        goto error_exit;
    }
    ptr = *((uint32_t*)(memory+offset + peb_offset - tasks_offset));
    munmap(memory, instance->page_size);

    /* copy appropriate values into peb struct */
    xa_read_long_virt(instance, ptr + iba_offset, pid, &(peb->ImageBaseAddress));
    xa_read_long_virt(instance, ptr + ph_offset, pid, &(peb->ProcessHeap));

    return XA_SUCCESS;

error_exit:
    if (memory) munmap(memory, instance->page_size);
    return XA_FAILURE;
}

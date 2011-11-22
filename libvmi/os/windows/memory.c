/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

status_t windows_symbol_to_address (
        vmi_instance_t vmi, char *symbol, addr_t *address)
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
        addr_t rva = *address;
        *address = vmi->os.windows_instance.ntoskrnl_va + rva;
        dbprint("--got symbol from PE export table (%s --> 0x%.16llx).\n", symbol, *address);
        return VMI_SUCCESS;
    }

    /*TODO check symbol server ??? */

    return VMI_FAILURE;
}

/* find the ntoskrnl base address */
#define NUM_BASE_ADDRESSES 11
addr_t get_ntoskrnl_base (vmi_instance_t vmi)
{
    addr_t paddr;
    int i = 0;

    /* Various base addresses that are known to exist across different
       versions of windows.  If you add to this list, be sure to change
       the value of NUM_BASE_ADDRESSES as well! */
    addr_t base_address[NUM_BASE_ADDRESSES] = {
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
            goto normal_exit;
        }
    }

    /* IDTR and work backwards */
#if 0 

// not sure if this will work (1) is idtr a VA or PA? (2) how to extract start
// addr from idtr?
    reg_t idtr = 0;
    if (VMI_FAILURE == vmi_get_vcpureg(vmi, &idtr, IDTR_BASE, 0)){
        dbprint("Failed to get idtr register\n");
        return 0;
    }
    printf("idtr=0x%llx\n", idtr);
    //paddr = (idtr & 0x0000FFFFFFFF0000ULL) >> 16; // 32 bit?
    paddr = aligned_addr (vmi, idtr);
    printf("first paddr=0x%llx\n", paddr);
    while (paddr != 0){
        printf("paddr=0x%llx\n", paddr);
        if (valid_ntoskrnl_start(vmi, paddr) == VMI_SUCCESS){
            goto normal_exit;
        }
        paddr -= vmi->page_size;
    }
#endif

    /* 0 and work forward */
    paddr = 0;
    while (paddr < vmi_get_memsize(vmi)){
        if (valid_ntoskrnl_start(vmi, paddr) == VMI_SUCCESS){
            printf("FOUND KERNEL at paddr=0x%llx\n", paddr);
            goto normal_exit;
        }
        paddr += vmi->page_size;
    }

error_exit:
    dbprint("--get_ntoskrnl_base failed\n");
    return 0;
normal_exit:
    return paddr;
}

/* finds the EPROCESS struct for a given pid */
uint32_t windows_get_EPROCESS (vmi_instance_t vmi, int pid)
{
    uint32_t list_head = 0, next_process = 0;
    int task_pid = 0;
    int pid_offset = vmi->os.windows_instance.pid_offset;
    int tasks_offset = vmi->os.windows_instance.tasks_offset;

    /* first we need a pointer to this pid's EPROCESS struct */
    next_process = vmi->init_task;

    while (1){
        uint32_t next_process_tmp = 0;
        vmi_read_32_va(vmi, next_process, 0, &next_process_tmp);

        /* if we are back at the list head, we are done */
        if (list_head == next_process_tmp){
            goto error_exit;
        }

        /* if pid matches, then we found what we want */
        vmi_read_32_va(vmi, next_process + pid_offset - tasks_offset, 0, &task_pid);
        if (task_pid == pid){
            return next_process;
        }

        next_process = next_process_tmp;
        if (!list_head){
            list_head = next_process;
        }
    }

error_exit:
    return 0;
}

/* finds the address of the page global directory for a given pid */
uint32_t windows_pid_to_pgd (vmi_instance_t vmi, int pid)
{
    uint32_t pgd = 0;
    uint32_t eprocess = 0;
    int pdbase_offset = vmi->os.windows_instance.pdbase_offset;
    int tasks_offset = vmi->os.windows_instance.tasks_offset;

    /* first we need a pointer to this pid's EPROCESS struct */
    eprocess = windows_get_EPROCESS(vmi, pid);
    if (!eprocess){
        errprint("Could not find EPROCESS struct for pid = %d.\n", pid);
        goto error_exit;
    }

    /* now follow the pointer to the memory descriptor and
       grab the pgd value */
    vmi_read_32_va(vmi, eprocess + pdbase_offset - tasks_offset, 0, &pgd);

error_exit:
    return pgd;
}

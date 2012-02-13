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
    if (vmi->kpgd){
        cr3 = vmi->kpgd;
    }
    else{
        driver_get_vcpureg(vmi, &cr3, CR3, 0);
    }
    dbprint("--windows symbol lookup (%s)\n", symbol);

    /* check kpcr if we have a cr3 */
    if (/*cr3 &&*/ VMI_SUCCESS == windows_kpcr_lookup(vmi, symbol, address)){
        dbprint("--got symbol from kpcr (%s --> 0x%lx).\n", symbol, *address);
        return VMI_SUCCESS;
    }
    dbprint("--kpcr lookup failed, trying kernel PE export table\n");

    /* check exports */
    if (VMI_SUCCESS == windows_export_to_rva(vmi, symbol, address)){
        addr_t rva = *address;
        *address = vmi->os.windows_instance.ntoskrnl_va + rva;
        dbprint("--got symbol from PE export table (%s --> 0x%.16llx).\n", symbol, *address);
        return VMI_SUCCESS;
    }
    dbprint("--kernel PE export table failed, nothing left to try\n");

    return VMI_FAILURE;
}

/* finds the EPROCESS struct for a given pid */
static addr_t windows_get_EPROCESS (vmi_instance_t vmi, int pid)
{
    addr_t list_head = 0, next_process = 0;
    int task_pid = 0;
    int pid_offset = vmi->os.windows_instance.pid_offset;
    int tasks_offset = vmi->os.windows_instance.tasks_offset;

    /* first we need a pointer to this pid's EPROCESS struct */
    next_process = vmi->init_task;

    while (1){
        addr_t next_process_tmp = 0;
        vmi_read_addr_va(vmi, next_process, 0, &next_process_tmp);

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
addr_t windows_pid_to_pgd (vmi_instance_t vmi, int pid)
{
    addr_t pgd = 0;
    addr_t eprocess = 0;
    int pdbase_offset = vmi->os.windows_instance.pdbase_offset;
    int tasks_offset = vmi->os.windows_instance.tasks_offset;

    /* first we need a pointer to this pid's EPROCESS struct */
    eprocess = windows_get_EPROCESS(vmi, pid);
    if (!eprocess){
        errprint("Could not find EPROCESS struct for pid = %d.\n", pid);
        goto error_exit;
    }

    /* now follow the pointer to the memory descriptor and grab the pgd value */
    vmi_read_addr_va(vmi, eprocess + pdbase_offset - tasks_offset, 0, &pgd);

error_exit:
    return pgd;
}

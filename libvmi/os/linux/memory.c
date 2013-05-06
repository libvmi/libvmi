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

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "private.h"

/* finds the task struct for a given pid */
static addr_t
linux_get_taskstruct_addr_from_pid(
    vmi_instance_t vmi,
    int pid)
{
    addr_t list_head = 0, next_process = 0;
    int task_pid = -1;
    int pid_offset = vmi->os.linux_instance.pid_offset;
    int tasks_offset = vmi->os.linux_instance.tasks_offset;

    /* First we need a pointer to the initial entry in the tasks list.
     * Note that this is task_struct->tasks, not the base addr
     *  of task_struct: task_struct base = $entry - tasks_offset.
     */
    next_process = vmi->init_task;
    list_head = next_process;

    do {
        vmi_read_32_va(vmi, next_process + pid_offset - tasks_offset, 0, &task_pid);

        /* if pid matches, then we found what we want */
        if (task_pid == pid) {
            return next_process - tasks_offset;
        }

        vmi_read_addr_va(vmi, next_process, 0, &next_process);

        /* if we are back at the list head, we are done */
    } while(list_head != next_process); 

error_exit:
    return 0;
}

static addr_t
linux_get_taskstruct_addr_from_pgd(
    vmi_instance_t vmi,
    addr_t pgd)
{
    addr_t list_head = 0, next_process = 0;
    addr_t task_pgd = 0;
    int tasks_offset = vmi->os.linux_instance.tasks_offset;
    int mm_offset = vmi->os.linux_instance.mm_offset;
    int pgd_offset = vmi->os.linux_instance.pgd_offset;

    /* First we need a pointer to the initial entry in the tasks list.
     * Note that this is task_struct->tasks, not the base addr
     *  of task_struct: task_struct base = $entry - tasks_offset. 
     */
    next_process = vmi->init_task;
    list_head = next_process;

    do {
        addr_t ptr = 0;
        vmi_read_addr_va(vmi, next_process + mm_offset - tasks_offset, 0, &ptr);
        vmi_read_addr_va(vmi, ptr + pgd_offset, 0, &task_pgd);
        task_pgd = vmi_translate_kv2p(vmi, task_pgd);

        if (task_pgd == pgd) {
            return next_process - tasks_offset;
        }

        vmi_read_addr_va(vmi, next_process, 0, &next_process);
        
        /* if we are back at the list head, we are done */
    } while (list_head != next_process);

error_exit:
    return 0;
}

/* finds the address of the page global directory for a given pid */
addr_t
linux_pid_to_pgd(
    vmi_instance_t vmi,
    int pid)
{
    addr_t ts_addr = 0, pgd = 0, ptr = 0;
    int mm_offset = vmi->os.linux_instance.mm_offset;
    int pgd_offset = vmi->os.linux_instance.pgd_offset;

    /* first we need a pointer to this pid's task_struct */
    ts_addr = linux_get_taskstruct_addr_from_pid(vmi, pid);
    if (!ts_addr) {
        errprint("Could not find task struct for pid = %d.\n", pid);
        goto error_exit;
    }

    /* now follow the pointer to the memory descriptor and grab the pgd value */
    vmi_read_addr_va(vmi, ts_addr + mm_offset, 0, &ptr);
    vmi_read_addr_va(vmi, ptr + pgd_offset, 0, &pgd);

    /* convert pgd into a machine address */
    pgd = vmi_translate_kv2p(vmi, pgd);

error_exit:
    return pgd;
}

int
linux_pgd_to_pid(
    vmi_instance_t vmi,
    addr_t pgd)
{
    int pid = -1;
    addr_t ts_addr = 0;
    int pid_offset = vmi->os.linux_instance.pid_offset;

    /* first we need a pointer to this pid's task_struct */
    ts_addr = linux_get_taskstruct_addr_from_pgd(vmi, pgd);
    if (!ts_addr) {
        errprint("Could not find task struct for pgd = 0x%"PRIx64".\n", pgd);
        goto error_exit;
    }

    /* now follow the pointer to the memory descriptor and grab the pid value */
    vmi_read_32_va(vmi, ts_addr + pid_offset, 0, &pid);

error_exit:
    return pid;
}

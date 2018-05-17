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
#include "os/linux/linux.h"
#include "driver/driver_wrapper.h"

/* finds the task struct for a given pid */
static addr_t
linux_get_taskstruct_addr_from_pid(
    vmi_instance_t vmi,
    vmi_pid_t pid)
{
    addr_t list_head = 0, next_process = 0;
    vmi_pid_t task_pid = -1;
    linux_instance_t linux_instance = NULL;
    int pid_offset = 0;
    int tasks_offset = 0;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No os_data initialized\n");
        return 0;
    }

    linux_instance = vmi->os_data;

    pid_offset = linux_instance->pid_offset;
    tasks_offset = linux_instance->tasks_offset;

    /* First we need a pointer to the initial entry in the tasks list.
     * Note that this is task_struct->tasks, not the base addr
     *  of task_struct: task_struct base = $entry - tasks_offset.
     */
    next_process = vmi->init_task;
    list_head = next_process;

    do {
        vmi_read_32_va(vmi, next_process + pid_offset, 0, (uint32_t*)&task_pid);

        /* if pid matches, then we found what we want */
        if (task_pid == pid) {
            return next_process;
        }

        vmi_read_addr_va(vmi, next_process + tasks_offset, 0, &next_process);
        next_process -= tasks_offset;

        /* if we are back at the list head, we are done */
    } while (list_head != next_process);

    return 0;
}

static addr_t
linux_get_taskstruct_addr_from_pgd(
    vmi_instance_t vmi,
    addr_t pgd)
{
    addr_t list_head = 0, next_process = 0;
    addr_t task_pgd = 0;
    uint8_t width = 0;
    int tasks_offset = 0;
    int mm_offset = 0;
    int pgd_offset = 0;
    linux_instance_t os = NULL;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No os_data initialized\n");
        return 0;
    }

    os = vmi->os_data;

    tasks_offset = os->tasks_offset;
    mm_offset = os->mm_offset;
    pgd_offset = os->pgd_offset;

    /* First we need a pointer to the initial entry in the tasks list.
     * Note that this is task_struct->tasks, not the base addr
     *  of task_struct: task_struct base = $entry - tasks_offset.
     */
    next_process = vmi->init_task;
    list_head = next_process;

    width = vmi_get_address_width(vmi);

    do {
        addr_t ptr = 0;
        vmi_read_addr_va(vmi, next_process + mm_offset, 0, &ptr);

        /* task_struct->mm is NULL when Linux is executing on the behalf
         * of a task, or if the task represents a kthread. In this context,
         * task_struct->active_mm is non-NULL and we can use it as
         * a fallback. task_struct->active_mm can be found very reliably
         * at task_struct->mm + 1 pointer width
         */
        if (!ptr && width)
            vmi_read_addr_va(vmi, next_process + mm_offset + width, 0, &ptr);
        vmi_read_addr_va(vmi, ptr + pgd_offset, 0, &task_pgd);

        if ( VMI_SUCCESS == vmi_translate_kv2p(vmi, task_pgd, &task_pgd) &&
                task_pgd == pgd)
            return next_process;

        vmi_read_addr_va(vmi, next_process + tasks_offset, 0, &next_process);
        next_process -= tasks_offset;

        /* if we are back at the list head, we are done */
    } while (list_head != next_process);

    return 0;
}

/* finds the address of the page global directory for a given pid */
status_t
linux_pid_to_pgd(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t *pgd)
{
    addr_t ts_addr = 0, ptr = 0;
    uint8_t width = 0;
    status_t rc = VMI_FAILURE;
    linux_instance_t linux_instance = NULL;
    int mm_offset = 0;
    int pgd_offset = 0;

    if (!vmi->os_data) {
        errprint("VMI_ERROR: No os_data initialized\n");
        return VMI_FAILURE;
    }

    linux_instance = vmi->os_data;

    mm_offset = linux_instance->mm_offset;
    pgd_offset = linux_instance->pgd_offset;

    /* first we the address of this PID's task_struct */
    ts_addr = linux_get_taskstruct_addr_from_pid(vmi, pid);
    if (!ts_addr) {
        errprint("Could not find task struct for pid = %d.\n", pid);
        return VMI_FAILURE;
    }

    /* now follow the pointer to the memory descriptor and grab the pgd value */
    rc = vmi_read_addr_va(vmi, ts_addr + mm_offset, 0, &ptr);
    if ( VMI_FAILURE == rc )
        return VMI_FAILURE;

    /* task_struct->mm is NULL when Linux is executing on the behalf
     * of a task, or if the task represents a kthread. In this context,
     * task_struct->active_mm is non-NULL and we can use it as
     * a fallback. task_struct->active_mm can be found very reliably
     * at task_struct->mm + 1 pointer width
     */
    if (!ptr) {
        switch (vmi->page_mode) {
            case VMI_PM_AARCH64:// intentional fall-through
            case VMI_PM_IA32E:
                width = 8;
                break;
            case VMI_PM_AARCH32:// intentional fall-through
            case VMI_PM_LEGACY: // intentional fall-through
            case VMI_PM_PAE:
                width = 4;
                break;
            default:
                return 0;
        };

        rc = vmi_read_addr_va(vmi, ts_addr + mm_offset + width, 0, &ptr);

        if ( VMI_FAILURE == rc || !ptr )
            return rc;
    }

    rc = vmi_read_addr_va(vmi, ptr + pgd_offset, 0, pgd);
    if ( VMI_FAILURE == rc )
        return rc;

    /* convert pgd into a machine address */
    return vmi_translate_kv2p(vmi, *pgd, pgd);
}

status_t
linux_pgd_to_pid(
    vmi_instance_t vmi,
    addr_t pgd,
    vmi_pid_t *pid)
{
    addr_t ts_addr = 0;
    linux_instance_t linux_instance = NULL;
    int pid_offset = 0;

    if (!vmi->os_data) {
        errprint("VMI_ERROR: No os_data initialized\n");
        return VMI_FAILURE;
    }

    linux_instance = vmi->os_data;
    pid_offset = linux_instance->pid_offset;

    /* set the PCID of the CR3 registers to get the kernel space page table of the process due to meltdown patch (https://en.wikipedia.org/wiki/Kernel_page-table_isolation) */
    pgd &= ~0x1fff;

    /* first we the address of the task_struct with this PGD */
    ts_addr = linux_get_taskstruct_addr_from_pgd(vmi, pgd);
    if (!ts_addr) {
        errprint("Could not find task struct for pgd = 0x%"PRIx64".\n", pgd);
        return VMI_FAILURE;
    }

    /* now follow the pointer to the memory descriptor and grab the pid value */
    return vmi_read_32_va(vmi, ts_addr + pid_offset, 0, (uint32_t*)pid);
}

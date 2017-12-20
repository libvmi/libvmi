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
#include "os/freebsd/freebsd.h"
#include "driver/driver_wrapper.h"

static addr_t
freebsd_get_taskstruct_addr_from_pid(
    vmi_instance_t vmi,
    vmi_pid_t pid)
{
    addr_t next_process = 0;
    vmi_pid_t task_pid = -1;
    freebsd_instance_t freebsd_instance = NULL;
    int pid_offset = 0;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No os_data initialized\n");
        return 0;
    }

    freebsd_instance = vmi->os_data;

    pid_offset = freebsd_instance->pid_offset;
    next_process = vmi->init_task;

    do {
        vmi_read_32_va(vmi, next_process + pid_offset, 0, (uint32_t*)&task_pid);

        if (task_pid == pid) {
            return next_process;
        }

        vmi_read_addr_va(vmi, next_process, 0, &next_process);

    } while (0 != next_process);

    return 0;
}

static addr_t
freebsd_get_taskstruct_addr_from_pgd(
    vmi_instance_t vmi,
    addr_t pgd)
{
    addr_t next_process = 0;
    addr_t task_pgd = 0;
    int vmspace_offset = 0;
    int pgd_offset = 0;
    int pmap_offset = 0;
    freebsd_instance_t os = NULL;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No os_data initialized\n");
        return 0;
    }

    os = vmi->os_data;

    vmspace_offset = os->vmspace_offset;
    pgd_offset = os->pgd_offset;
    pmap_offset = os->pmap_offset;

    next_process = vmi->init_task;

    do {
        addr_t ptr = 0;
        vmi_read_addr_va(vmi, next_process + vmspace_offset, 0, &ptr);

        vmi_read_addr_va(vmi, ptr + pmap_offset + pgd_offset, 0, &task_pgd);

        if (task_pgd == pgd) {
            return next_process;
        }

        vmi_read_addr_va(vmi, next_process, 0, &next_process);

    } while (0 != next_process);

    return 0;
}


status_t
freebsd_pid_to_pgd(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t *pgd)
{
    addr_t proc_addr = 0, ptr = 0;
    status_t rc = VMI_FAILURE;
    freebsd_instance_t freebsd_instance = NULL;
    int vmspace_offset = 0;
    int pmap_offset = 0;
    int pgd_offset = 0;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No os_data initialized\n");
        return 0;
    }

    freebsd_instance = vmi->os_data;

    vmspace_offset = freebsd_instance->vmspace_offset;
    pgd_offset = freebsd_instance->pgd_offset;
    pmap_offset = freebsd_instance->pmap_offset;

    proc_addr = freebsd_get_taskstruct_addr_from_pid(vmi, pid);
    if (!proc_addr) {
        errprint("Could not find task struct for pid = %d.\n", pid);
        return VMI_FAILURE;
    }

    /* now follow the pointer to the memory descriptor and grab the pgd value */
    rc = vmi_read_addr_va(vmi, proc_addr + vmspace_offset, 0, &ptr);
    if ( VMI_FAILURE == rc )
        return VMI_FAILURE;

    rc = vmi_read_addr_va(vmi, ptr + pmap_offset + pgd_offset, 0, pgd);
    if ( VMI_FAILURE == rc )
        return VMI_FAILURE;

    return VMI_SUCCESS;
}

status_t
freebsd_pgd_to_pid(
    vmi_instance_t vmi,
    addr_t pgd,
    vmi_pid_t *pid)
{
    addr_t proc_addr = 0;
    freebsd_instance_t freebsd_instance = NULL;
    int pid_offset = 0;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No os_data initialized\n");
        return VMI_FAILURE;
    }

    freebsd_instance = vmi->os_data;
    pid_offset = freebsd_instance->pid_offset;

    /* first we the address of the task_struct with this PGD */
    proc_addr = freebsd_get_taskstruct_addr_from_pgd(vmi, pgd);
    if (!proc_addr) {
        errprint("Could not find task struct for pgd = 0x%"PRIx64".\n", pgd);
        return VMI_FAILURE;
    }

    /* now follow the pointer to the memory descriptor and grab the pid value */
    return vmi_read_32_va(vmi, proc_addr + pid_offset, 0, (uint32_t*)pid);
}

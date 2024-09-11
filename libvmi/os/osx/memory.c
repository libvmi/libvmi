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
#include "os/osx/osx.h"
#include "driver/driver_wrapper.h"


static addr_t proc_get_task_raw(addr_t proc, size_t proc_struct_size);
static status_t pgd_for_proc(vmi_instance_t vmi, addr_t proc, addr_t *pgd,addr_t *__unused);

static status_t pgd_for_proc(vmi_instance_t vmi, addr_t proc, addr_t *pgd,addr_t *pm_ucr3)
{
    /*
     * On xnu the pmap struct is found on the task struct.
     * Hence, we first need to get the task from process.
     * then to retrieve the vm_map and pmap, eventually cr3.
     *
        (lldb) p (proc_t)0xffffff8b4d8fecc0
        (proc_t) $0 = 0xffffff8b4d8fecc
        (lldb) p $0->p_proc_ro->pr_task->map->pmap->pm_cr3    <---- short way to convert proc->task is to use `proc_get_task_raw`
        (pmap_paddr_t) $6 = 5292462080

        sometimes cr3 value will be stored in pmap->pm_ucr3.
     * */
    status_t status = VMI_FAILURE;
    osx_instance_t osx_instance = vmi->os_data;
    osx_offsets_t *offsets = &osx_instance->offsets;
    addr_t _vm_map = 0;
    addr_t pmap = 0;

    addr_t task = proc_get_task_raw(proc, osx_instance->proc_size);

    CHECK_SUCCESS(vmi_read_addr_va(vmi, task + offsets->vmspace, 0, &_vm_map));
    CHECK_SUCCESS(vmi_read_addr_va(vmi, _vm_map + offsets->pmap, 0, &pmap));
    CHECK_SUCCESS(vmi_read_addr_va(vmi, pmap + offsets->pgd, 0, pgd));
    if (pm_ucr3 != NULL) {
        CHECK_SUCCESS(vmi_read_addr_va(vmi, pmap + offsets->pm_ucr3, 0, pm_ucr3));
    }
    status = VMI_SUCCESS;
done:
    return status;
}


status_t osx_pid_to_pgd(vmi_instance_t vmi, vmi_pid_t pid, addr_t *pgd)
{

    addr_t current;
    addr_t next_proc = 0;
    addr_t list_head = 0;
    status_t status = VMI_FAILURE;
    vmi_pid_t pid_tmp = -1;

    osx_instance_t osx_instance = NULL;

    CHECK((vmi->os_data != NULL));

    osx_instance = vmi->os_data;
    osx_offsets_t *offsets = &osx_instance->offsets;


    CHECK_SUCCESS(vmi_read_addr_va(vmi, vmi->init_task, 0, &list_head));

    for (current = list_head; current != 0; current = next_proc) {
        CHECK_SUCCESS(vmi_read_addr_va(vmi, current, 0, &next_proc));
        CHECK_SUCCESS(vmi_read_32_va(vmi, current + offsets->p_pid, 0, (uint32_t *) &pid_tmp));
        if (pid != pid_tmp) {
            continue;
        }
        CHECK_SUCCESS(pgd_for_proc(vmi, current, pgd,NULL));
        status = VMI_SUCCESS;
        break;
    }

done:
    return status;
}


status_t osx_pgd_to_pid(vmi_instance_t vmi, addr_t pgd, vmi_pid_t *pid)
{

    addr_t next_proc = 0;
    addr_t list_head = 0;
    addr_t tmp_pgd = 0;
    addr_t tmp_ucr3 = 0;
    addr_t current;
    status_t status = VMI_FAILURE;
    osx_instance_t osx_instance = NULL;

    CHECK((vmi->os_data != NULL));

    osx_instance = vmi->os_data;
    osx_offsets_t *offsets = &osx_instance->offsets;

    CHECK_SUCCESS(vmi_read_addr_va(vmi, vmi->init_task, 0, &list_head));

    for (current = list_head; current != 0; current = next_proc) {
        CHECK_SUCCESS(vmi_read_addr_va(vmi, current, 0, &next_proc));
        CHECK_SUCCESS(vmi_read_32_va(vmi, current + offsets->p_pid, 0, (uint32_t *) pid));
        CHECK_SUCCESS(pgd_for_proc(vmi, current, &tmp_pgd,&tmp_ucr3));

        // pgd value can be store both on pmap->pm_cr3 and pmap->pm_ucr3
        if (pgd != tmp_pgd && pgd != tmp_ucr3) {
            continue;
        }

        status = VMI_SUCCESS;
        break;
    }

done:
    return status;
}

// https://github.com/apple-oss-distributions/xnu/blob/aca3beaa3dfbd42498b42c5e5ce20a938e6554e5/bsd/kern/kern_proc.c#L4
static addr_t proc_get_task_raw(addr_t proc, size_t proc_struct_size)
{
    return (addr_t) (proc + proc_struct_size);
}
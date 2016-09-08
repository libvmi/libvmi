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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>

#include <libvmi/libvmi.h>

int main (int argc, char **argv)
{
    vmi_instance_t vmi;
    addr_t list_head = 0, next_list_entry = 0;
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;
    status_t status;

    /* this is the VM or file that we are looking at */
    if (argc != 2) {
        printf("Usage: %s <vmname>\n", argv[0]);
        return 1;
    } // if

    char *name = argv[1];

    /* initialize the libvmi library */
    if (vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    /* init the offset values */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
        tasks_offset = vmi_get_offset(vmi, "linux_tasks");
        name_offset = vmi_get_offset(vmi, "linux_name");
        pid_offset = vmi_get_offset(vmi, "linux_pid");
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {
        tasks_offset = vmi_get_offset(vmi, "win_tasks");
        name_offset = vmi_get_offset(vmi, "win_pname");
        pid_offset = vmi_get_offset(vmi, "win_pid");
    }

    if (0 == tasks_offset) {
        printf("Failed to find win_tasks\n");
        goto error_exit;
    }
    if (0 == pid_offset) {
        printf("Failed to find win_pid\n");
        goto error_exit;
    }
    if (0 == name_offset) {
        printf("Failed to find win_pname\n");
        goto error_exit;
    }

    /* pause the vm for consistent memory access */
    if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to pause VM\n");
        goto error_exit;
    } // if

    /* demonstrate name and id accessors */
    char *name2 = vmi_get_name(vmi);

    if (VMI_FILE != vmi_get_access_mode(vmi)) {
        uint64_t id = vmi_get_vmid(vmi);

        printf("Process listing for VM %s (id=%"PRIu64")\n", name2, id);
    }
    else {
        printf("Process listing for file %s\n", name2);
    }
    free(name2);

    /* get the head of the list */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
        /* Begin at PID 0, the 'swapper' task. It's not typically shown by OS
         *  utilities, but it is indeed part of the task list and useful to
         *  display as such.
         */
        list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset;
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {

        // find PEPROCESS PsInitialSystemProcess
        if(VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
            printf("Failed to find PsActiveProcessHead\n");
            goto error_exit;
        }
    }

    next_list_entry = list_head;

    /* walk the task list */
    do {

        current_process = next_list_entry - tasks_offset;

        /* Note: the task_struct that we are looking at has a lot of
         * information.  However, the process name and id are burried
         * nice and deep.  Instead of doing something sane like mapping
         * this data to a task_struct, I'm just jumping to the location
         * with the info that I want.  This helps to make the example
         * code cleaner, if not more fragile.  In a real app, you'd
         * want to do this a little more robust :-)  See
         * include/linux/sched.h for mode details */

        /* NOTE: _EPROCESS.UniqueProcessId is a really VOID*, but is never > 32 bits,
         * so this is safe enough for x64 Windows for example purposes */
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);

        if (!procname) {
            printf("Failed to find procname\n");
            goto error_exit;
        }

        /* print out the process name */
        printf("[%5d] %s (struct addr:%"PRIx64")\n", pid, procname, current_process);
        if (procname) {
            free(procname);
            procname = NULL;
        }

        /* follow the next pointer */

        status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
            goto error_exit;
        }

    } while(next_list_entry != list_head);

error_exit:
    /* resume the vm */
    vmi_resume_vm(vmi);

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    return 0;
}

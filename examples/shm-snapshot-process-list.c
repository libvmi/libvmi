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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>

#include <libvmi/libvmi.h>
#include <libvmi/shm.h>

void list_processes(vmi_instance_t vmi, addr_t current_process,
                    addr_t list_head, unsigned long tasks_offset, addr_t current_list_entry,
                    addr_t next_list_entry, unsigned long pid_offset,
                    vmi_pid_t pid, char* procname, unsigned long name_offset)
{
    vmi_mode_t mode;

    /* demonstrate name and id accessors */
    char* name2 = vmi_get_name(vmi);
    if (VMI_FAILURE == vmi_get_access_mode(vmi, NULL, 0, NULL, &mode))
        return;

    if ( VMI_FILE != mode ) {
        uint64_t id = vmi_get_vmid(vmi);

        printf("Process listing for VM %s (id=%"PRIu64")\n", name2, id);
    } else {
        printf("Process listing for file %s\n", name2);
    }
    free(name2);
    /* get the head of the list */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
        /* Begin at PID 0, the 'swapper' task. It's not typically shown by OS
         *  utilities, but it is indeed part of the task list and useful to
         *  display as such.
         */
        vmi_translate_ksym2v(vmi, "init_task", &current_process);
    } else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {
        // find PEPROCESS PsInitialSystemProcess
        vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);
    }

    /* walk the task list */
    list_head = current_process + tasks_offset;
    current_list_entry = list_head;
    status_t status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
    if (status == VMI_FAILURE) {
        printf("Failed to read next pointer at 0x%"PRIx64" before entering loop\n",
               current_list_entry);
        goto error_exit;
    }
    printf("Next list entry is at: %"PRIx64"\n", next_list_entry);
    do {
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

        current_list_entry = next_list_entry;
        current_process = current_list_entry - tasks_offset;

        /* follow the next pointer */

        status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n",
                   current_list_entry);
            goto error_exit;
        }

    } while (next_list_entry != list_head);
error_exit:
    if (procname)
        free(procname);
}

int main (int argc, char **argv)
{
    /* this is the VM or file that we are looking at */
    if (argc != 2) {
        printf("Usage: %s <vmname>\n", argv[0]);
        return 1;
    }

#if ENABLE_SHM_SNAPSHOT == 1
    vmi_instance_t vmi;
    addr_t list_head = 0, current_list_entry = 0, next_list_entry = 0;
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    unsigned long tasks_offset, pid_offset, name_offset;

    char *name = argv[1];

    /* initialize the libvmi library */
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME, NULL,
                              VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    /* init the offset values */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
        if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_tasks", &tasks_offset) )
            goto error_exit;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_name", &name_offset) )
            goto error_exit;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_pid", &pid_offset) )
            goto error_exit;

        /* NOTE:
         *  name_offset is no longer hard-coded. Rather, it is now set
         *  via libvmi.conf.
         */
    } else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {
        if ( VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks_offset) )
            goto error_exit;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pname", &name_offset) )
            goto error_exit;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pid", &pid_offset) )
            goto error_exit;
    }

    /* create a shm-snapshot */
    if (vmi_shm_snapshot_create(vmi) != VMI_SUCCESS) {
        printf("Failed to shm-snapshot VM\n");
        goto error_exit;
    }

    /* demonstrate name and id accessors */
    list_processes(vmi, current_process, list_head, tasks_offset,
                   current_list_entry, next_list_entry, pid_offset, pid,
                   procname, name_offset);

error_exit:
    if (procname)
        free(procname);

    /* destroy the shm-snapshot, and return live mode */
    vmi_shm_snapshot_destroy(vmi);

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    return 0;
#else
    printf("Error : this example should only run after ./configure --enable-shm-snapshot.\n");
    return 1; // error
#endif

}

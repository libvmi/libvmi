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

#include <libvmi/libvmi.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>

int main (int argc, char **argv)
{
    vmi_instance_t vmi;
    unsigned char *memory = NULL;
    uint32_t offset;
    addr_t next_process, list_head;
    char *procname = NULL;
    int pid = 0;
    int tasks_offset, pid_offset, name_offset;
    status_t status;

    /* this is the VM or file that we are looking at */
    if (argc != 2) {
        printf ("Usage: %s <vmname>\n", argv[0]);
        return 1;
    } // if

    char *name = argv[1];

    /* initialize the libvmi library */
    if (vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, name) == VMI_FAILURE){
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }

    /* init the offset values */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)){
        tasks_offset = vmi_get_offset(vmi, "linux_tasks");
        name_offset = vmi_get_offset(vmi, "linux_name");
        pid_offset = vmi_get_offset(vmi, "linux_pid");
	
        /* NOTE: 
         *  name_offset is no longer hard-coded. Rather, it is now set 
         *  via libvmi.conf.
         */
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)){
        tasks_offset = vmi_get_offset(vmi, "win_tasks");
        if (0 == tasks_offset) {
            printf("Failed to find win_tasks\n");
            goto error_exit;
        }
        name_offset = vmi_get_offset(vmi, "win_pname");
        if (0 == tasks_offset) {
            printf("Failed to find win_pname\n");
            goto error_exit;
        }
        pid_offset = vmi_get_offset(vmi, "win_pid");
        if (0 == tasks_offset) {
            printf("Failed to find win_pid\n");
            goto error_exit;
        }
    }

    /* pause the vm for consistent memory access */
    if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to pause VM\n");
        goto error_exit;
    } // if

    /* demonstrate name and id accessors */
    char *name2 = vmi_get_name(vmi);
    if (VMI_FILE != vmi_get_access_mode(vmi)){
        unsigned long id = vmi_get_vmid(vmi);
        printf("Process listing for VM %s (id=%lu)\n", name2, id);
    }
    else{
        printf("Process listing for file %s\n", name2);
    }
    free(name2);

    /* get the head of the list */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)){
        addr_t init_task_va = vmi_translate_ksym2v(vmi, "init_task");
        vmi_read_addr_va(vmi, init_task_va + tasks_offset, 0, &next_process);
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)){

        uint32_t pdbase = 0;

        // find PEPROCESS PsInitialSystemProcess
        vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &list_head); 
        
        vmi_read_addr_va(vmi, list_head + tasks_offset, 0, &next_process);
        vmi_read_32_va(vmi, list_head + pid_offset, 0, &pid);

        vmi_read_32_va(vmi, list_head + pid_offset, 0, &pid);
        procname = vmi_read_str_va(vmi, list_head + name_offset, 0);
        if (!procname) {
            printf ("Failed to find first procname\n");
            goto error_exit;
        }

        printf("[%5d] %s\n", pid, procname);
        if (procname){
            free(procname);
            procname = NULL;
        }
    }

    list_head = next_process;

    /* walk the task list */
    while (1){

        /* follow the next pointer */
        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_process, 0, &tmp_next);

        /* if we are back at the list head, we are done */
        if (list_head == tmp_next){
            break;
        }

        /* print out the process name */

        /* Note: the task_struct that we are looking at has a lot of
           information.  However, the process name and id are burried
           nice and deep.  Instead of doing something sane like mapping
           this data to a task_struct, I'm just jumping to the location
           with the info that I want.  This helps to make the example
           code cleaner, if not more fragile.  In a real app, you'd
           want to do this a little more robust :-)  See
           include/linux/sched.h for mode details */
        procname = vmi_read_str_va(vmi, next_process + name_offset - tasks_offset, 0);

        if (!procname) {
            printf ("Failed to find procname\n");
        } // if

        vmi_read_32_va(vmi, next_process + pid_offset - tasks_offset, 0, &pid);

        /* trivial sanity check on data */
        if (pid >= 0 && procname){
            printf("[%5d] %s\n", pid, procname);
        }
        if (procname){
            free(procname);
            procname = NULL;
        }
        next_process = tmp_next;
    }

error_exit:
    if (procname) free(procname);

    /* resume the vm */
    vmi_resume_vm(vmi);

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    return 0;
}

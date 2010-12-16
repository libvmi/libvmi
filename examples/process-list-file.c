/*
 * Copyright (C) 2005 - 2007  Bryan D. Payne (bryan@thepaynes.cc)
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
 * This file provides a simple example for walking through the list
 * of tasks or processes in a guest domain.  This uses a memory file
 * instead of working from a live xen VM.
 *
 * File: process-list-file.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <xenaccess/xenaccess.h>
#include <xenaccess/xa_private.h>

/* offset to each of these fields from the beginning of the struct
   assuming that CONFIG_SCHEDSTATS is not defined  and CONFIG_KEYS
   is defined in the guest's kernel (this is the default in xen) */
#define TASKS_OFFSET 24 * 4   /* task_struct->tasks */
#define PID_OFFSET 39 * 4     /* task_struct->pid */
#define NAME_OFFSET 108 * 4   /* task_struct->comm */

/* offsets for Windows XP SP2.  These can be looked up using windbg
   using the following command:  dt _eprocess -r1 */
#define ActiveProcessLinks_OFFSET 0x88
#define UniqueProcessId_OFFSET 0x84
#define ImageFileName_OFFSET 0x174

int main (int argc, char **argv)
{
    xa_instance_t xai;
    unsigned char *memory = NULL;
    uint32_t offset, next_process, list_head;
    char *name = NULL;
    int pid = 0;

    /* this is the file that we are looking at */
    char *filename = argv[1];

    /* initialize the xen access library */
    if (xa_init_file_strict(filename, "WinXP-HVM", &xai) == XA_FAILURE){
        perror("failed to init XenAccess library");
        goto error_exit;
    }

    /* get the head of the list */
    if (XA_OS_LINUX == xai.os_type){
        memory = xa_access_kernel_sym(&xai, "init_task", &offset, PROT_READ);
        if (NULL == memory){
            perror("failed to get process list head");
            goto error_exit;
        }    
        memcpy(&next_process, memory + offset + TASKS_OFFSET, 4);
    }
    else if (XA_OS_WINDOWS == xai.os_type){
        list_head = windows_find_eprocess(&xai, "System");
        memory = xa_access_pa(&xai, list_head, &offset, PROT_READ);
        if (NULL == memory){
            perror("failed to get EPROCESS for PsInitialSystemProcess");
            goto error_exit;
        }
        memcpy(&next_process, memory + offset + ActiveProcessLinks_OFFSET, 4);
        name = (char *) (memory + offset + ImageFileName_OFFSET);
        memcpy(&pid, memory + offset + UniqueProcessId_OFFSET, 4);
        printf("[%5d] %s\n", pid, name);
    }
    list_head = next_process;
    munmap(memory, xai.page_size);

    /* walk the task list */
    while (1){

        /* follow the next pointer */
        memory = xa_access_kernel_va(&xai, next_process, &offset, PROT_READ);
        if (NULL == memory){
            perror("failed to map memory for process list pointer");
            goto error_exit;
        }
        memcpy(&next_process, memory + offset, 4);

        /* if we are back at the list head, we are done */
        if (list_head == next_process){
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
        if (XA_OS_LINUX == xai.os_type){
            name = (char *) (memory + offset + NAME_OFFSET - TASKS_OFFSET);
            memcpy(&pid, memory + offset + PID_OFFSET - TASKS_OFFSET, 4);
        }

        /* Same note applies to the way that Windows data is parsed */
        else if (XA_OS_WINDOWS == xai.os_type){
            name = (char *) (memory + offset + ImageFileName_OFFSET -
                   ActiveProcessLinks_OFFSET);
            memcpy(&pid, memory + offset + UniqueProcessId_OFFSET -
                   ActiveProcessLinks_OFFSET, 4);
        }

        /* trivial sanity check on data */
        if (pid < 0){
            continue;
        }
        printf("[%5d] %s\n", pid, name);
        munmap(memory, xai.page_size);
    }

error_exit:

    /* sanity check to unmap shared pages */
    if (memory) munmap(memory, xai.page_size);

    /* cleanup any memory associated with the XenAccess instance */
    xa_destroy(&xai);

    return 0;
}


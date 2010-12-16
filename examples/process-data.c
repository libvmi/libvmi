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
 * This file provides a simple example for view the application data
 * inside the userspace-level memory of a process.
 *
 * File: process-data.c
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

void linux_printaddr (xa_linux_taskaddr_t taskaddr)
{
    printf("start_code = 0x%.8lx\n", taskaddr.start_code);
    printf("end_code = 0x%.8lx\n", taskaddr.end_code);
    printf("start_data = 0x%.8lx\n", taskaddr.start_data);
    printf("end_data = 0x%.8lx\n", taskaddr.end_data);
    printf("start_brk = 0x%.8lx\n", taskaddr.start_brk);
    printf("brk = 0x%.8lx\n", taskaddr.brk);
    printf("start_stack = 0x%.8lx\n", taskaddr.start_stack);
    printf("arg_stack = 0x%.8lx\n", taskaddr.arg_stack);
    printf("arg_end = 0x%.8lx\n", taskaddr.arg_end);
    printf("env_start = 0x%.8lx\n", taskaddr.env_start);
    printf("env_end = 0x%.8lx\n", taskaddr.env_end);
}

void windows_printaddr (xa_windows_peb_t peb)
{
    printf("ImageBaseAddress = 0x%.8x\n", peb.ImageBaseAddress);
    printf("ProcessHeap = 0x%.8x\n", peb.ProcessHeap);
}

int main (int argc, char **argv)
{
    xa_instance_t xai;
    xa_linux_taskaddr_t taskaddr;
    xa_windows_peb_t peb;
    unsigned char *memory = NULL;
    uint32_t offset = 0;

    /* this is the domain ID that we are looking at */
    uint32_t dom = atoi(argv[1]);

    /* This is the pid that we are looking at, passed as
       an argument on the command line. */
    int pid = atoi(argv[2]);

    /* initialize the xen access library */
    if (xa_init_vm_id_strict(dom, &xai) == XA_FAILURE){
        perror("failed to init XenAccess library");
        goto error_exit;
    }

    /* get the relavent addresses for this process */
    if (XA_OS_LINUX == xai.os_type){
        if (xa_linux_get_taskaddr(&xai, pid, &taskaddr) == XA_FAILURE){
            perror("failed to get task addresses");
            goto error_exit;
        }
    }
    else if (XA_OS_WINDOWS == xai.os_type){
        if (xa_windows_get_peb(&xai, pid, &peb) == XA_FAILURE){
            perror("failed to get process addresses from peb");
            goto error_exit;
        }
    }

    /* print out the process address information */
    printf("Memory descriptor addresses for pid = %d:\n", pid);
    if (XA_OS_LINUX == xai.os_type){
        linux_printaddr(taskaddr);
    }
    else if (XA_OS_WINDOWS == xai.os_type){
        windows_printaddr(peb);
    }

    /* grab the memory at the start of the code segment
       for this process and print it out */
    if (XA_OS_LINUX == xai.os_type){
        memory = xa_access_user_va(
                 &xai, taskaddr.start_code, &offset, pid, PROT_READ);
    }
    else if (XA_OS_WINDOWS == xai.os_type){
        memory = xa_access_user_va(
                 &xai, peb.ImageBaseAddress, &offset, pid, PROT_READ);
    }
    if (NULL == memory){
        perror("failed to map memory");
        goto error_exit;
    }
    print_hex(memory, xai.page_size);
    printf("offset = 0x%x\n", offset);

error_exit:

    /* sanity check to unmap shared pages */
    if (memory) munmap(memory, xai.page_size);

    /* cleanup any memory associated with the XenAccess instance */
    xa_destroy(&xai);

    return 0;
}


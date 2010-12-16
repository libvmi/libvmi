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
 * of modules in a guest domain.
 *
 * File: module-list.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <xenaccess/xenaccess.h>

/* len and addr should be from a _UNICODE_STRING struct where len is the 
   'Length' field and addr is the 'Buffer' field */
void print_unicode_string (xa_instance_t *xai, uint16_t len, uint32_t addr)
{
    //below is a total hack to bypass unicode support
    int i = 0;
    uint32_t offset = 0;
    char *tmpname = malloc(len);
    char *name = malloc(len);
    unsigned char *memory =
        xa_access_kernel_va(xai, addr, &offset, PROT_READ);

    if (memory){
        memset(name, 0, len);
        memcpy(tmpname, memory + offset, len);
        munmap(memory, xai->page_size);
        for (i = 0; i < len; i++){
            if (i%2 == 0){
                name[i/2] = tmpname[i];
            }
        }
        printf("%s\n", name);
    }
    if (name) free(name);
    if (tmpname) free(tmpname);
}

int main (int argc, char **argv)
{
    xa_instance_t xai;
    unsigned char *memory = NULL;
    uint32_t offset, next_module, list_head;
    char *name = NULL;

    /* this is the domain ID that we are looking at */
    uint32_t dom = atoi(argv[1]);

    /* initialize the xen access library */
    if (xa_init_vm_id_strict(dom, &xai) == XA_FAILURE){
        perror("failed to init XenAccess library");
        goto error_exit;
    }

    /* get the head of the module list */
    if (XA_OS_LINUX == xai.os_type){
        xa_read_long_sym(&xai, "modules", &next_module);
    }
    else if (XA_OS_WINDOWS == xai.os_type){
        /*TODO don't use a hard-coded address here */
        if (xai.pae){
            memory = xa_access_kernel_va(&xai, 0x805533a0, &offset, PROT_READ);
        }
        else{
            memory = xa_access_kernel_va(&xai, 0x8055a620, &offset, PROT_READ);
        }
        if (NULL == memory){
            perror("failed to get PsLoadedModuleList");
            goto error_exit;
        }
        memcpy(&next_module, memory + offset, 4);
        munmap(memory, xai.page_size);
    }
    list_head = next_module;

    /* walk the module list */
    while (1){

        /* follow the next pointer */
        memory = xa_access_kernel_va(&xai, next_module, &offset, PROT_READ);
        if (NULL == memory){
            perror("failed to map memory for module list pointer");
            goto error_exit;
        }
        memcpy(&next_module, memory + offset, 4);

        /* if we are back at the list head, we are done */
        if (list_head == next_module){
            break;
        }

        /* print out the module name */

        /* Note: the module struct that we are looking at has a string
           directly following the next / prev pointers.  This is why you
           can just add 8 to get the name.  See include/linux/module.h
           for mode details */
        if (XA_OS_LINUX == xai.os_type){
            name = (char *) (memory + offset + 8);
            printf("%s\n", name);
        }
        else if (XA_OS_WINDOWS == xai.os_type){
            /*TODO don't use a hard-coded offsets here */
            /* these offsets work with WinXP SP2 */
            uint16_t length;
            uint32_t buffer_addr;
            memcpy(&length, memory + offset + 0x2c, 2);
            memcpy(&buffer_addr, memory + offset + 0x30, 4);
            print_unicode_string(&xai, length, buffer_addr);
        }
        munmap(memory, xai.page_size);
    }

error_exit:

    /* sanity check to unmap shared pages */
    if (memory) munmap(memory, xai.page_size);

    /* cleanup any memory associated with the XenAccess instance */
    xa_destroy(&xai);

    return 0;
}


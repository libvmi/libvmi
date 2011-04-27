/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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

#define PAGE_SIZE 1 << 12

/* len and addr should be from a _UNICODE_STRING struct where len is the 
   'Length' field and addr is the 'Buffer' field */
void print_unicode_string (vmi_instance_t vmi, uint16_t len, addr_t addr)
{
    //below is a total hack to bypass unicode support
    int i = 0;
    uint32_t offset = 0;
    char *tmpname = malloc(len);
    char *name = malloc(len);
    if (len == vmi_read_va(vmi, addr, 0, tmpname, len)){
        memset(name, 0, len);
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
    vmi_instance_t vmi;
    uint32_t offset;
    addr_t next_module, list_head;

    /* this is the VM or file that we are looking at */
    char *name = argv[1];

    /* initialize the libvmi library */
    if (vmi_init(&vmi, VMI_MODE_AUTO, name) == VMI_FAILURE){
        perror("failed to init LibVMI library");
        goto error_exit;
    }

    /* pause the vm for consistent memory access */
    vmi_pause_vm(vmi);

    /* get the head of the module list */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)){
        vmi_read_32_ksym(vmi, "modules", &next_module);
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)){
        vmi_read_32_ksym(vmi, "PsLoadedModuleList", &next_module);
    }
    list_head = next_module;

    /* walk the module list */
    while (1){

        /* follow the next pointer */
        addr_t tmp_next = 0;
        vmi_read_32_va(vmi, next_module, 0, &tmp_next);

        /* if we are back at the list head, we are done */
        if (list_head == tmp_next){
            break;
        }

        /* print out the module name */

        /* Note: the module struct that we are looking at has a string
           directly following the next / prev pointers.  This is why you
           can just add 8 to get the name.  See include/linux/module.h
           for mode details */
        if (VMI_OS_LINUX == vmi_get_ostype(vmi)){
            char *modname = vmi_read_str_va(vmi, next_module + 8, 0);
            printf("%s\n", modname);
            free(modname);
        }
        else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)){
            /*TODO don't use a hard-coded offsets here */
            /* these offsets work with WinXP SP2 */
            uint16_t length;
            addr_t buffer_addr;
            vmi_read_va(vmi, next_module + 0x2c, 0, &length, 2);
            vmi_read_va(vmi, next_module + 0x30, 0, &buffer_addr, 4);
            print_unicode_string(vmi, length, buffer_addr);
        }
        next_module = tmp_next;
    }

error_exit:
    /* resume the vm */
    vmi_resume_vm(vmi);

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    return 0;
}

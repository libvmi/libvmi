/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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
void print_unicode_string (vmi_instance_t vmi, uint16_t len, uint32_t addr)
{
    //below is a total hack to bypass unicode support
    int i = 0;
    uint32_t offset = 0;
    char *tmpname = malloc(len);
    char *name = malloc(len);
    unsigned char *memory =
        vmi_access_kernel_va(vmi, addr, &offset, PROT_READ);

    if (memory){
        memset(name, 0, len);
        memcpy(tmpname, memory + offset, len);
        munmap(memory, PAGE_SIZE);
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
    unsigned char *memory = NULL;
    uint32_t offset, next_module, list_head;
    char *modname = NULL;

    /* this is the VM or file that we are looking at */
    char *name = argv[1];

    /* initialize the libvmi library */
    if (vmi_init_name(&vmi, VMI_MODE_AUTO, name) == VMI_FAILURE){
        perror("failed to init LibVMI library");
        goto error_exit;
    }

    /* get the head of the module list */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)){
        vmi_read_long_sym(vmi, "modules", &next_module);
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)){
        vmi_read_long_sym(vmi, "PsLoadedModuleList", &next_module);
    }
    list_head = next_module;

    /* walk the module list */
    while (1){

        /* follow the next pointer */
        memory = vmi_access_kernel_va(vmi, next_module, &offset, PROT_READ);
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
        if (VMI_OS_LINUX == vmi_get_ostype(vmi)){
            modname = (char *) (memory + offset + 8);
            printf("%s\n", modname);
        }
        else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)){
            /*TODO don't use a hard-coded offsets here */
            /* these offsets work with WinXP SP2 */
            uint16_t length;
            uint32_t buffer_addr;
            memcpy(&length, memory + offset + 0x2c, 2);
            memcpy(&buffer_addr, memory + offset + 0x30, 4);
            print_unicode_string(vmi, length, buffer_addr);
        }
        munmap(memory, PAGE_SIZE);
    }

error_exit:

    /* sanity check to unmap shared pages */
    if (memory) munmap(memory, PAGE_SIZE);

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    return 0;
}

/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include "libvmi.h"
#include "private.h"

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

char *windows_get_eprocess_name (vmi_instance_t vmi, uint32_t paddr)
{
    int name_length = 16; //TODO verify that this is correct for all versions
    uint32_t name_paddr = paddr + 0x174; //TODO make this work on all versions
    char *name = (char *) safe_malloc(name_length);

    if (name_length == vmi_read_pa(vmi, name_paddr, name, name_length)){
        return name;
    }
    else{
        free(name);
        return NULL;
    }
}

uint32_t windows_find_eprocess (vmi_instance_t vmi, char *name)
{
    uint32_t offset = 0;
    uint32_t value = 0;

    while (offset < vmi->size){
        vmi_read_32_pa(vmi, offset, &value);
        // Magic header numbers.  See get_ntoskrnl_base for
        // an explanation.
        if (value == 0x001b0003 || value == 0x00200003){
            char *procname = windows_get_eprocess_name(vmi, offset);
            if (procname){
                if (strncmp(procname, name, 50) == 0){
                    free(procname);
                    return offset;
                }
                free(procname);
            }
        }
        offset += 8;
    }
    return 0;
}

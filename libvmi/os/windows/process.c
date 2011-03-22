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
    uint32_t name_paddr = paddr + 0x174; /*TODO replace hard coded value */
    uint32_t offset = 0;
    char *memory = vmi_access_pa(vmi, name_paddr, &offset, PROT_READ);
    if (memory){
        char *name = memory + offset;
        return strndup(name, 50);
    }
    return NULL;
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

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

char *windows_get_eprocess_name (vmi_instance_t instance, uint32_t paddr)
{
    uint32_t name_paddr = paddr + 0x174; /*TODO replace hard coded value */
    uint32_t offset = 0;
    char *memory = vmi_access_pa(instance, name_paddr, &offset, PROT_READ);
    if (memory){
        char *name = memory + offset;
        return strndup(name, 50);
    }
    return NULL;
}

uint32_t windows_find_eprocess (vmi_instance_t instance, char *name)
{
    uint32_t end = 0;
    uint32_t offset = 0;
    uint32_t value = 0;

    if (VMI_MODE_XEN == instance->mode){
#ifdef ENABLE_XEN
        end = instance->m.xen.size;
#endif /* ENABLE_XEN */
    }
    else if (VMI_MODE_FILE == instance->mode){
        end = instance->m.file.size;
    }
    
    while (offset < end){
        vmi_read_long_phys(instance, offset, &value);
        // Magic header numbers.  See get_ntoskrnl_base for
        // an explanation.
        if (value == 0x001b0003 || value == 0x00200003){
            char *procname = windows_get_eprocess_name(instance, offset);
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

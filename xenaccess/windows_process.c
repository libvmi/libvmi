/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2008  Bryan D. Payne (bryan@thepaynes.cc)
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
 * This file contains utility functions for printing out data and
 * debugging information.
 *
 * File: windows_process.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "xenaccess.h"

char *windows_get_eprocess_name (xa_instance_t *instance, uint32_t paddr)
{
    uint32_t name_paddr = paddr + 0x174; /*TODO replace hard coded value */
    uint32_t offset = 0;
    char *memory = xa_access_pa(instance, name_paddr, &offset, PROT_READ);
    if (memory){
        char *name = memory + offset;
        return strndup(name, 50);
    }
    return NULL;
}

uint32_t windows_find_eprocess (xa_instance_t *instance, char *name)
{
    uint32_t end = 0;
    uint32_t offset = 0;
    uint32_t value = 0;

    if (XA_MODE_XEN == instance->mode){
#ifdef ENABLE_XEN
        end = instance->m.xen.size;
#endif /* ENABLE_XEN */
    }
    else if (XA_MODE_FILE == instance->mode){
        end = instance->m.file.size;
    }
    
    while (offset < end){
        xa_read_long_phys(instance, offset, &value);
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

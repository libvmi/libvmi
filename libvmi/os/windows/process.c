/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
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

#include "libvmi.h"
#include "private.h"

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

char *windows_get_eprocess_name (vmi_instance_t vmi, uint32_t paddr)
{
    int name_length = 16; //TODO verify that this is correct for all versions
    uint32_t name_paddr = paddr + vmi->os.windows_instance.pname_offset;
    char *name = (char *) safe_malloc(name_length);

    if (name_length == vmi_read_pa(vmi, name_paddr, name, name_length)){
        return name;
    }
    else{
        free(name);
        return NULL;
    }
}

int find_pname_offset (vmi_instance_t vmi)
{
    uint32_t offset = 0;
    uint32_t value = 0;

    while (offset < vmi->size){
        vmi_read_32_pa(vmi, offset, &value);
        // Magic header numbers.
        if (value == 0x001b0003 || value == 0x00200003){
            int i = 0;
            for ( ; i < 0x500; ++i){
                char *procname = vmi_read_str_pa(vmi, offset + i);
                if (NULL == procname){
                    continue;
                }
                else if (strncmp(procname, "Idle", 4) == 0){
                    free(procname);
                    return i;
                }
                else{
                    free(procname);
                }
            }
        }
        offset += 8;
    }
    return 0;
}

uint32_t windows_find_eprocess (vmi_instance_t vmi, char *name)
{
    uint32_t offset = 0;
    uint32_t value = 0;

    if (vmi->os.windows_instance.pname_offset == 0){
        vmi->os.windows_instance.pname_offset = find_pname_offset(vmi);
        if (vmi->os.windows_instance.pname_offset == 0){
            dbprint("--failed to find pname_offset\n");
            return 0;
        }
    }

    while (offset < vmi->size){
        vmi_read_32_pa(vmi, offset, &value);
        // Magic header numbers.
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

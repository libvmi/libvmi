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

#define MAGIC1 0x1b0003
#define MAGIC2 0x200003
#define MAGIC3 0x580003
static inline int check_magic_2k (uint32_t a) { return (a == MAGIC1); }
static inline int check_magic_xp (uint32_t a) { return (a == MAGIC1); }
static inline int check_magic_2k3 (uint32_t a) { return (a == MAGIC1); }
static inline int check_magic_vista (uint32_t a) { return (a == MAGIC2); }
static inline int check_magic_2k8 (uint32_t a) { return (a == MAGIC1 || a == MAGIC2 || a == MAGIC3); } // not sure what this is, check all
static inline int check_magic_7 (uint32_t a) { return (a == MAGIC3); }
static inline int check_magic_unknown (uint32_t a) { return (a == MAGIC1 || a == MAGIC2 || a == MAGIC3); }

static check_magic_func get_check_magic_func (vmi_instance_t vmi)
{
    check_magic_func rtn = NULL;

    switch (vmi->os.windows_instance.version) {
        case VMI_OS_WINDOWS_2000:
            rtn = &check_magic_2k;
            break;
        case VMI_OS_WINDOWS_XP:
            rtn = &check_magic_xp;
            break;
        case VMI_OS_WINDOWS_2003:
            rtn = &check_magic_2k3;
            break;
        case VMI_OS_WINDOWS_VISTA:
            rtn = &check_magic_vista;
            break;
        case VMI_OS_WINDOWS_2008:
            rtn = &check_magic_2k8;
            break;
        case VMI_OS_WINDOWS_7:
            rtn = &check_magic_7;
            break;
        case VMI_OS_WINDOWS_UNKNOWN:
            rtn = &check_magic_unknown;
            break;
        default:
            rtn = &check_magic_unknown;
            dbprint("--%s: illegal value in vmi->os.windows_instance.version\n", __FUNCTION__);
            break;
    }

    return rtn;
}

int find_pname_offset (vmi_instance_t vmi, check_magic_func check)
{
    uint32_t offset = 0;
    uint32_t value = 0;
    uint32_t target_val = 0;

    if (NULL == check){
        check = get_check_magic_func(vmi);
    }

    while (offset < vmi->size){
        vmi_read_32_pa(vmi, offset, &value);

        if (check(value)) { // look for specific magic #
            dbprint("--%s: found magic value 0x%.8x @ offset 0x%.8x\n", __FUNCTION__, value, offset);

            int i = 0;
            for ( ; i < 0x500; ++i){
                char *procname = vmi_read_str_pa(vmi, offset + i);
                if (NULL == procname){
                    continue;
                }
                else if (strncmp(procname, "Idle", 4) == 0){
                    vmi->init_task = offset + vmi->os.windows_instance.tasks_offset;
                    dbprint("--%s: found Idle process at 0x%.8x + 0x%x\n", __FUNCTION__, offset, i);
                    free(procname);
                    return i;
                }
                else{
                    free(procname);
                }
            } // for
        } // if
        offset += 8;
    } // while
    return 0;
}

uint32_t windows_find_eprocess (vmi_instance_t vmi, char *name)
{
    uint32_t offset = 0;
    uint32_t value = 0;
    check_magic_func check = get_check_magic_func(vmi);

    if (vmi->os.windows_instance.pname_offset == 0){
        vmi->os.windows_instance.pname_offset = find_pname_offset(vmi, check);
        if (vmi->os.windows_instance.pname_offset == 0){
            dbprint("--failed to find pname_offset\n");
            return 0;
        }
        else{
            dbprint("**set os.windows_instance.pname_offset (0x%x)\n", vmi->os.windows_instance.pname_offset);
        }
    }

    if (vmi->init_task){
        offset = vmi->init_task - vmi->os.windows_instance.tasks_offset;
    }

    while (offset < vmi->size){
        vmi_read_32_pa(vmi, offset, &value);
        if (check(value)){ // look for specific magic #
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

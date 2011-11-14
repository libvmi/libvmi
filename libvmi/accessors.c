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
#include "driver/interface.h"

uint32_t vmi_get_access_mode (vmi_instance_t vmi)
{
    return vmi->flags & 0x0000FFFF;
}

os_t vmi_get_ostype (vmi_instance_t vmi)
{
    return vmi->os_type;
}

unsigned long vmi_get_offset (vmi_instance_t vmi, char *offset_name)
{
    size_t max_length = 100;

    if (strncmp(offset_name, "win_tasks", max_length) == 0){
        return vmi->os.windows_instance.tasks_offset;
    }
    else if (strncmp(offset_name, "win_pdbase", max_length) == 0){
        return vmi->os.windows_instance.pdbase_offset;
    }
    else if (strncmp(offset_name, "win_pid", max_length) == 0){
        return vmi->os.windows_instance.pid_offset;
    }
    else if (strncmp(offset_name, "win_pname", max_length) == 0){
        if (vmi->os.windows_instance.pname_offset == 0){
            vmi->os.windows_instance.pname_offset = find_pname_offset(vmi, NULL);
            if (vmi->os.windows_instance.pname_offset == 0){
                dbprint("--failed to find pname_offset\n");
                return 0;
            }
        }
        return vmi->os.windows_instance.pname_offset;
    }
    else if (strncmp(offset_name, "linux_tasks", max_length) == 0){
        return vmi->os.linux_instance.tasks_offset;
    }
    else if (strncmp(offset_name, "linux_mm", max_length) == 0){
        return vmi->os.linux_instance.mm_offset;
    }
    else if (strncmp(offset_name, "linux_pid", max_length) == 0){
        return vmi->os.linux_instance.pid_offset;
    }
    else if (strncmp(offset_name, "linux_pgd", max_length) == 0){
        return vmi->os.linux_instance.pgd_offset;
    }
    else{
        warnprint("Invalid offset name in vmi_get_offset (%s).\n", offset_name);
        return 0;
    }
}

unsigned long vmi_get_memsize (vmi_instance_t vmi)
{
    return vmi->size;
}

status_t vmi_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    return driver_get_vcpureg(vmi, value, reg, vcpu);
}

status_t vmi_pause_vm (vmi_instance_t vmi)
{
    return driver_pause_vm(vmi);
}

status_t vmi_resume_vm (vmi_instance_t vmi)
{
    return driver_resume_vm(vmi);
}

/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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

/* NB: Necessary for windows specific API functions */
#include "os/windows/windows.h"

page_mode_t
vmi_get_page_mode(
    vmi_instance_t vmi)
{
    if(vmi->page_mode == VMI_PM_UNKNOWN) {
        page_mode_t ret=VMI_PM_UNKNOWN;
        get_memory_layout(vmi, &ret, NULL, NULL, NULL);
        return ret;
    } else {
        return vmi->page_mode;
    }
}

uint8_t vmi_get_address_width(
    vmi_instance_t vmi)
{
    uint8_t width = 0;

    driver_get_address_width(vmi, &width);

    return width;
}

uint32_t
vmi_get_access_mode(
    vmi_instance_t vmi)
{
    return vmi->mode;
}

os_t
vmi_get_ostype(
    vmi_instance_t vmi)
{
    return vmi->os_type;
}

win_ver_t
vmi_get_winver(
    vmi_instance_t vmi)
{
    windows_instance_t windows_instance = NULL;

    if (VMI_OS_WINDOWS != vmi->os_type || (VMI_INIT_PARTIAL & vmi->init_mode))
        return VMI_OS_WINDOWS_NONE;

    if (!vmi->os_data) {
        return VMI_OS_WINDOWS_NONE;
    }

    windows_instance = vmi->os_data;

    if (!windows_instance->version
            || windows_instance->version == VMI_OS_WINDOWS_UNKNOWN) {
        windows_instance->version = find_windows_version(vmi,
                windows_instance->kdversion_block);
    }
    return windows_instance->version;
}

const char *
vmi_get_winver_str(
    vmi_instance_t vmi)
{
    win_ver_t ver = vmi_get_winver(vmi);

    switch (ver) {
    case VMI_OS_WINDOWS_NONE:
        return "VMI_OS_WINDOWS_NONE";
    case VMI_OS_WINDOWS_UNKNOWN:
        return "VMI_OS_WINDOWS_UNKNOWN";
    case VMI_OS_WINDOWS_2000:
        return "VMI_OS_WINDOWS_2000";
    case VMI_OS_WINDOWS_XP:
        return "VMI_OS_WINDOWS_XP";
    case VMI_OS_WINDOWS_2003:
        return "VMI_OS_WINDOWS_2003";
    case VMI_OS_WINDOWS_VISTA:
        return "VMI_OS_WINDOWS_VISTA";
    case VMI_OS_WINDOWS_2008:
        return "VMI_OS_WINDOWS_2008";
    case VMI_OS_WINDOWS_7:
        return "VMI_OS_WINDOWS_7";
    default:
        return "<Illegal value for Windows version>";
    }   // switch
}

win_ver_t
vmi_get_winver_manual(
    vmi_instance_t vmi,
    addr_t kdvb_pa)
{
    return find_windows_version(vmi, kdvb_pa);
}

uint64_t
vmi_get_offset(
    vmi_instance_t vmi,
    char *offset_name)
{
    size_t max_length = 100;

    if (vmi->os_interface == NULL || vmi->os_interface->os_get_offset == NULL ) {
        return 0;
    }

    return vmi->os_interface->os_get_offset(vmi, offset_name);
}

unsigned long
vmi_get_memsize(
    vmi_instance_t vmi)
{
    return vmi->size;
}

unsigned int
vmi_get_num_vcpus(
    vmi_instance_t vmi)
{
    return vmi->num_vcpus;
}

status_t
vmi_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu)
{
    return driver_get_vcpureg(vmi, value, reg, vcpu);
}

status_t
vmi_set_vcpureg(
    vmi_instance_t vmi,
    reg_t value,
    registers_t reg,
    unsigned long vcpu)
{
    return driver_set_vcpureg(vmi, value, reg, vcpu);
}

status_t
vmi_pause_vm(
    vmi_instance_t vmi)
{
    return driver_pause_vm(vmi);
}

status_t
vmi_resume_vm(
    vmi_instance_t vmi)
{
    return driver_resume_vm(vmi);
}

#if ENABLE_SHM_SNAPSHOT == 1
status_t
vmi_shm_snapshot_create(
		vmi_instance_t vmi)
{
	return driver_shm_snapshot_vm(vmi);
}

status_t
vmi_shm_snapshot_destroy(
		vmi_instance_t vmi)
{
	return driver_destroy_shm_snapshot_vm(vmi);
}
#endif

char *
vmi_get_name(
    vmi_instance_t vmi)
{
    /* memory for name is allocated at the driver level */
    char *name = NULL;

    if (VMI_FAILURE == driver_get_name(vmi, &name)) {
        return NULL;
    }
    else {
        return name;
    }
}

unsigned long
vmi_get_vmid(
    vmi_instance_t vmi)
{
    unsigned long domid = VMI_INVALID_DOMID;
    if(VMI_INVALID_DOMID == (domid = driver_get_id(vmi))) {
        char *name = vmi_get_name(vmi);
        domid = driver_get_id_from_name(vmi, name);
        free(name);
    }

    return domid;
}

/* The LibVMI Library is an introspection library that simplifies access to
* memory in a target virtual machine or in a file containing a dump of
* a system's physical memory.  LibVMI is based on the XenAccess Library.
*
* Author: Kevin Mayer (kevin.mayer@gdata.de)
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

#include "private.h"
#include "driver/driver_wrapper.h"

status_t vmi_slat_get_domain_state (vmi_instance_t vmi, bool *state)
{
    return driver_slat_get_domain_state (vmi, state);
}

status_t vmi_slat_set_domain_state (vmi_instance_t vmi, bool state)
{
    return driver_slat_set_domain_state (vmi, state);
}

status_t vmi_slat_create (vmi_instance_t vmi, uint16_t *slat_id)
{
    return driver_slat_create (vmi, slat_id);
}

status_t vmi_slat_destroy (vmi_instance_t vmi, uint16_t slat_idx)
{
    return driver_slat_destroy (vmi, slat_idx);
}

status_t vmi_slat_switch (vmi_instance_t vmi, uint16_t slat_idx)
{
    return driver_slat_switch (vmi, slat_idx);
}

status_t vmi_slat_change_gfn (vmi_instance_t vmi, uint16_t slat_idx, addr_t old_gfn, addr_t new_gfn)
{
    return driver_slat_change_gfn (vmi, slat_idx, old_gfn, new_gfn);
}

status_t vmi_slat_create_physical_page (vmi_instance_t vmi, uint64_t *page_addr)
{
	return driver_slat_create_physical_page (vmi, page_addr);
}

status_t vmi_slat_destroy_physical_page (vmi_instance_t vmi, uint64_t page_addr)
{
	return driver_slat_destroy_physical_page (vmi, page_addr);
}

uint64_t vmi_slat_get_max_gpfn (vmi_instance_t vmi)
{
	return driver_slat_get_max_gpfn (vmi);
}

status_t vmi_slat_init (vmi_instance_t vmi, uint64_t *init_memsize)
{
	return driver_slat_init (vmi, init_memsize);
}

status_t vmi_slat_deinit(vmi_instance_t vmi, uint64_t init_memsize)
{
	return driver_slat_deinit(vmi, init_memsize);
}
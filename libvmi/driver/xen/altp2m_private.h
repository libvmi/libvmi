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

/**
* @file altp2m_private.h
* @brief The functions concerning themself with the control of xens altp2m
* are defined here.
*
*/

#ifndef ALTP2M_PRIVATE_H
#define ALTP2M_PRIVATE_H

#include "private.h"

status_t xen_altp2m_get_domain_state (vmi_instance_t vmi, bool *state);
status_t xen_altp2m_set_domain_state (vmi_instance_t vmi, bool state);
status_t xen_altp2m_create_p2m (vmi_instance_t vmi, uint16_t *altp2m_idx);
status_t xen_altp2m_destroy_p2m (vmi_instance_t vmi, uint16_t altp2m_idx);
status_t xen_altp2m_switch_p2m (vmi_instance_t vmi, uint16_t altp2m_idx);
status_t xen_altp2m_change_gfn (vmi_instance_t vmi,
                                uint16_t altp2m_idx,
                                addr_t old_gfn,
                                addr_t new_gfn);

static inline void
xen_init_altp2m (
    vmi_instance_t vmi )
{
    xen_instance_t *xen = xen_get_instance ( vmi );

    if ( xen->major_version > 4 || ( xen->major_version == 4 && xen->minor_version >= 6 ) ) {
        vmi->driver.slat_get_domain_state_ptr = &xen_altp2m_get_domain_state;
        vmi->driver.slat_set_domain_state_ptr = &xen_altp2m_set_domain_state;
        vmi->driver.slat_create_ptr = &xen_altp2m_create_p2m;
        vmi->driver.slat_destroy_ptr = &xen_altp2m_destroy_p2m;
        vmi->driver.slat_switch_ptr = &xen_altp2m_switch_p2m;
        vmi->driver.slat_change_gfn_ptr = &xen_altp2m_change_gfn;
    }
}

#endif

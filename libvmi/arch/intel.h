/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
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

#ifndef INTEL_H
#define INTEL_H

#include "private.h"

status_t v2p_nopae (vmi_instance_t vmi, addr_t npt, page_mode_t npm, addr_t pt, addr_t vaddr, page_info_t *info);
status_t v2p_pae (vmi_instance_t vmi, addr_t npt, page_mode_t npm, addr_t pt, addr_t vaddr, page_info_t *info);

GSList* get_pages_nopae(vmi_instance_t vmi, addr_t npt, page_mode_t npm, addr_t dtb);
GSList* get_pages_pae(vmi_instance_t vmi, addr_t npt, page_mode_t npm, addr_t dtb);

/* checks for EPT misconfiguration in page_access_flag */
status_t intel_mem_access_sanity_check(vmi_mem_access_t page_access_flag);

#endif

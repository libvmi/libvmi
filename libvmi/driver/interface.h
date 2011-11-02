/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
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
#include <stdlib.h>

status_t driver_init_mode (vmi_instance_t vmi, unsigned long id, char *name);
status_t driver_init (vmi_instance_t vmi);
void driver_destroy (vmi_instance_t vmi);
unsigned long driver_get_id_from_name (vmi_instance_t vmi, char *name);
unsigned long driver_get_id (vmi_instance_t vmi);
void driver_set_id (vmi_instance_t vmi, unsigned long id);
status_t driver_get_name (vmi_instance_t vmi, char **name);
void driver_set_name (vmi_instance_t vmi, char *name);
status_t driver_get_memsize (vmi_instance_t vmi, unsigned long *size);
status_t driver_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu);
addr_t driver_pfn_to_mfn (vmi_instance_t vmi, addr_t pfn);
void *driver_read_page (vmi_instance_t vmi, addr_t page);
status_t driver_write (vmi_instance_t vmi, addr_t paddr, void *buf, uint32_t length);
int driver_is_pv (vmi_instance_t vmi);
status_t driver_pause_vm (vmi_instance_t vmi);
status_t driver_resume_vm (vmi_instance_t vmi);

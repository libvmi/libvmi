/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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
unsigned long driver_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn);
void *driver_map_page (vmi_instance_t vmi, int prot, unsigned long page);
int driver_is_pv (vmi_instance_t vmi);
status_t driver_pause_vm (vmi_instance_t vmi);
status_t driver_resume_vm (vmi_instance_t vmi);

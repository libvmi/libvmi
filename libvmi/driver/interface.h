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

typedef unsigned long reg_t;

typedef enum registers{
    REG_CR0,
    REG_CR1,
    REG_CR2,
    REG_CR3,
    REG_CR4
} registers_t;

status_t driver_init (vmi_instance_t vmi);
void driver_destroy (vmi_instance_t vmi);
unsigned long driver_get_id (vmi_instance_t vmi);
void driver_set_id (vmi_instance_t vmi, unsigned long id);
status_t driver_get_name (vmi_instance_t vmi, char **name);
void driver_set_name (vmi_instance_t vmi, char *name);
status_t driver_get_memsize (vmi_instance_t vmi, unsigned long *size);
status_t driver_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu);

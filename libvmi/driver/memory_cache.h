/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include "libvmi.h"
#include "private.h"

void memory_cache_init (
        void *(*get_data)(vmi_instance_t, uint32_t, uint32_t),
        void (*release_data)(void *, size_t),
        unsigned long age_limit
);
void *memory_cache_insert (vmi_instance_t vmi, uint32_t paddr, uint32_t *offset);

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
#include <stdio.h>
#include <sys/mman.h>

void *vmi_map_file_range (vmi_instance_t instance, int prot, unsigned long pfn)
{
    void *memory = NULL;
    long address = pfn << instance->page_shift;
    int fildes = fileno(instance->m.file.fhandle);

    if (address >= instance->m.file.size){
        return NULL;
    }

    memory = mmap(NULL, instance->page_size, prot, MAP_SHARED, fildes, address);
    if (MAP_FAILED == memory){
        perror("file.c: file mmap failed");
        return NULL;
    }
    return memory;
}

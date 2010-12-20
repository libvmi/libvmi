/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include <stdio.h>
#include <sys/mman.h>
#include "libvmi.h"

void *xa_map_file_range (xa_instance_t *instance, int prot, unsigned long pfn)
{
    void *memory = NULL;
    long address = pfn << instance->page_shift;
    int fildes = fileno(instance->m.file.fhandle);

    if (address >= instance->m.file.size){
        return NULL;
    }

    memory = mmap(NULL, instance->page_size, prot, MAP_SHARED, fildes, address);
    if (MAP_FAILED == memory){
        perror("xa_file.c: file mmap failed");
        return NULL;
    }
    return memory;
}

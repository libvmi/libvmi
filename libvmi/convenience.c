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
#include <stdarg.h>
#include <stdlib.h>

#ifndef VMI_DEBUG
/* Nothing */
#else
void dbprint(char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}
#endif

/* prints an error message to stderr */
void errprint (char* format, ...){
    va_list args;
    fprintf(stderr, "VMI_ERROR: ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

/* prints a warning message to stderr */
void warnprint (char* format, ...){
    va_list args;
    fprintf(stderr, "VMI_WARNING: ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

void *safe_malloc_ (size_t size, char const *file, int line)
{
    void *p = malloc(size);
    if (NULL == p){
        errprint("malloc %lu bytes failed at %s:%d\n", (unsigned long)size, file, line);
        exit(EXIT_FAILURE);
   }
   return p;
}

unsigned long get_reg32 (reg_t r)
{
    return (unsigned long) r;
}

int vmi_get_bit (unsigned long reg, int bit)
{
    unsigned long mask = 1 << bit;
    if (reg & mask){
        return 1;
    }
    else{
        return 0;
    }
}


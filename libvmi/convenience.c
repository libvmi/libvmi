/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
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

int vmi_get_bit (reg_t reg, int bit)
{
    reg_t mask = 1 << bit;
    if (reg & mask){
        return 1;
    }
    else{
        return 0;
    }
}

addr_t p2m (vmi_instance_t vmi, addr_t paddr)
{
    addr_t maddr = 0;

    uint32_t pfn = paddr >> vmi->page_shift;
    uint32_t offset = (vmi->page_size - 1) & paddr;
    uint32_t mfn = driver_pfn_to_mfn(vmi, pfn);

    maddr = mfn << vmi->page_shift;
    maddr |= offset;
    return maddr;
}

addr_t aligned_addr (vmi_instance_t vmi, addr_t addr)
{
    addr_t mask = ~((addr_t)vmi->page_size-1);
    addr_t aligned = (addr_t)addr & (addr_t)mask;
//    printf ("%llx & %llx = %llx\n", addr, mask, aligned);
    return aligned;

}

int is_addr_aligned (vmi_instance_t vmi, addr_t addr)
{
    return (addr == aligned_addr(vmi, addr));
}



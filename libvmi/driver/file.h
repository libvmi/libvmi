/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

typedef struct file_instance{
    FILE *fhandle;       /**< handle to the memory image file */
    uint32_t size;       /**< total size of file, in bytes */
} file_instance_t;

status_t file_set_memsize (vmi_instance_t vmi);

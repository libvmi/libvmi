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
    char *filename;      /**< name of the file being accessed */
} file_instance_t;

status_t file_init (vmi_instance_t vmi);
void file_set_name (vmi_instance_t vmi, char *name);
status_t file_get_memsize (vmi_instance_t vmi, unsigned long *size);

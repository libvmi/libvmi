/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#ifdef ENABLE_FILE
#include "libvmi.h"
#include "private.h"
#include "driver/file.h"
#define _GNU_SOURCE
#include <string.h>

//----------------------------------------------------------------------------
// File-Specific Interface Functions (no direction mapping to driver_*)

file_instance_t file_get_instance(vmi_instance_t vmi)
{
    file_instance_t fileinst = (file_instance_t) vmi->driver;
    return fileinst;
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t file_init (vmi_instance_t vmi)
{
    FILE *fhandle = NULL;

    /* open handle to memory file */
    if ((fhandle = fopen(filename, "rb")) == NULL){
        errprint("Failed to open file for reading.\n");
        return VMI_FAILURE;
    }
    instance->m.file.fhandle = fhandle;

}

void file_set_name (vmi_instance_t vmi, char *name)
{
    file_get_instance().filename = strndup(name, 500);
}

status_t file_get_memsize (vmi_instance_t vmi, unsigned long *size)
{
    status_t ret = VMI_FAILURE;
    struct stat s;

    if (fstat(fileno(file_get_instance(vmi).fhandle), &s) == -1){
        fprintf(stderr, "ERROR: Failed to stat file\n");
        goto error_exit;
    }
    *size = (unsigned long) s.st_size;
    dbprint("**set instance->driver.size = %d\n", size);
    ret = VMI_SUCCESS;

error_exit:
    return ret;
}

//////////////////////////////////////////////////////////////////////
#else

status_t file_init (vmi_instance_t vmi) {return VMI_FAILURE; }
void file_set_name (vmi_instance_t vmi, char *name) {return; }
status_t file_get_memsize (vmi_instance_t vmi, unsigned long size) { return VMI_FAILURE; }

#endif /* ENABLE_FILE */

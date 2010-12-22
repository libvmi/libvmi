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

file_instance_t file_get_instance(vmi_instance_t vmi)
{
    file_instance_t fileinst = (file_instance_t) vmi->driver;
    return fileinst;
}

status_t file_set_memsize (vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;
    unsigned long size = 0;
    struct stat s;

    if (fstat(fileno(file_get_instance(vmi).fhandle), &s) == -1){
        fprintf(stderr, "ERROR: Failed to stat file\n");
        goto error_exit;
    }
    file_get_instance(vmi).size = (uint32_t) s.st_size;
    dbprint("**set instance->driver.size = %d\n", size);
    ret = VMI_SUCCESS;

error_exit:
    return ret;
}

//////////////////////////////////////////////////////////////////////
#else

status_t file_set_memsize (vmi_instance_t vmi) { return VMI_FAILURE; }

#endif /* ENABLE_FILE */

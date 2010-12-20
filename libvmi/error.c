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

/* updates the errno value to the given value */
void xa_set_errno (int error){
// do nothing for now... not using errno just yet
//    errno = error;
}

/* prints an error message to stderr */
void xa_errprint (char* format, ...){
    va_list args;
    fprintf(stderr, "XA_ERROR: ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

/* prints a warning message to stderr */
void xa_warnprint (char* format, ...){
    va_list args;
    fprintf(stderr, "XA_WARNING: ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

int xa_report_error (xa_instance_t *instance, int error, int error_type){
    int ret = 0;

    /* determine how to set the return value */
    if (instance->error_mode == XA_FAILHARD){
        ret = XA_FAILURE;
    }
    else if (instance->error_mode == XA_FAILSOFT){
        if (error_type == XA_ECRITICAL){
            ret = XA_FAILURE;
        }
        else{
            ret = XA_SUCCESS;
        }
    }
    else{
        xa_dbprint("BUG: invalid mode\n");
        ret = XA_FAILURE;
    }

    /* report to errno */
    if (XA_FAILURE == ret){
        xa_set_errno(error);
    }

    /* return the return value to be used by the library */
    return ret;
}

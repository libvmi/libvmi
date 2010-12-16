/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2008  Bryan D. Payne (bryan@thepaynes.cc)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * --------------------
 * This file contains utility functions handling return values
 * and other details associated with error handling.
 *
 * File: xa_error.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 */

#include "xenaccess.h"
#include "xa_private.h"
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

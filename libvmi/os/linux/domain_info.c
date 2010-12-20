/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include "private.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef ENABLE_XEN
#include <xs.h>
#endif /* ENABLE_XEN */

char *linux_predict_sysmap_name (uint32_t id)
{
    char *kernel = NULL;
    char *sysmap = NULL;
    int length = 0;
    int i = 0;

    kernel = xa_get_kernel_name(id);
    if (NULL == kernel){
        fprintf(stderr, "ERROR: could not get kernel name for domain id %d\n", id);
        goto error_exit;
    }

    /* we can't predict for hvm domains */
    else if (strcmp(kernel, "/usr/lib/xen/boot/hvmloader") == 0){
        goto error_exit;
    }

    /* replace 'vmlinuz' with 'System.map' */
    length = strlen(kernel) + 4;
    sysmap = malloc(length);
    memset(sysmap, 0, length);
    for (i = 0; i < length; ++i){
        if (strncmp(kernel + i, "vmlinu", 6) == 0){
            strcat(sysmap, "System.map");
            strcat(sysmap, kernel + i + 7);
            break;
        }
        else{
            sysmap[i] = kernel[i];
        }
    }

error_exit:
    if (kernel) free(kernel);
    return sysmap;
}

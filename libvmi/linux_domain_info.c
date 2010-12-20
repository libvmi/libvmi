/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2007  Bryan D. Payne (bryan@thepaynes.cc)
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
 * This file contains utility functions for collecting information
 * from the domains.  Most of this high-level information is
 * gathered using the libvirt library (http://libvirt.org).
 *
 * File: linux_domain_info.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 *
 * $Id: linux_domain_info.c 190 2009-01-25 20:41:07Z hajime.inoue $
 * $Date$
 */
#include "xa_private.h"

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

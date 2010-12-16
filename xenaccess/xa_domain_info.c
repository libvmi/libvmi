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
 * File: xa_domain_info.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 *
 * $Id: xa_domain_info.c 179 2008-12-19 18:46:47Z bdpayne $
 * $Date$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */


#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef ENABLE_XEN
#include <xs.h>

char *xa_get_vmpath (int id)
{
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *tmp = NULL;
    char *vmpath = NULL;

    tmp = malloc(100);
    if (NULL == tmp){
        goto error_exit;
    }

    /* get the vm path */
    memset(tmp, 0, 100);
    sprintf(tmp, "/local/domain/%d/vm", id);
    xsh = xs_domain_open();
    vmpath = xs_read(xsh, xth, tmp, NULL);

error_exit:
    /* cleanup memory here */
    if (tmp) free(tmp);
    if (xsh) xs_daemon_close(xsh);

    return vmpath;
}

char *xa_get_kernel_name (int id)
{
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *vmpath = NULL;
    char *kernel = NULL;
    char *tmp = NULL;

    vmpath = xa_get_vmpath(id);

    /* get the kernel name */
    tmp = malloc(100);
    if (NULL == tmp){
        goto error_exit;
    }
    memset(tmp, 0, 100);
    sprintf(tmp, "%s/image/kernel", vmpath);
    xsh = xs_domain_open();
    kernel = xs_read(xsh, xth, tmp, NULL);

error_exit:
    /* cleanup memory here */
    if (tmp) free(tmp);
    if (vmpath) free(vmpath);
    if (xsh) xs_daemon_close(xsh);

    return kernel;
}

/*TODO use Xen version info to to correct test the first time */
int xa_ishvm (int id)
{
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *vmpath = NULL;
    char *ostype = NULL;
    char *tmp = NULL;
    unsigned int len = 0;
    int ret = 0;

    /* setup initial values */
    vmpath = xa_get_vmpath(id);
    xsh = xs_domain_open();
    tmp = malloc(100);
    if (NULL == tmp){
        goto exit;
    }

    /* check the value for xen 3.2.x and earlier */
    memset(tmp, 0, 100);
    sprintf(tmp, "%s/image/kernel", vmpath);
    ostype = xs_read(xsh, xth, tmp, &len);
    if (NULL == ostype){
        /* no action */
    }
    else if (fnmatch("*hvmloader", ostype, 0) == 0){
        ret = 1;
        goto exit;
    }

    /* try again using different path for 3.3.x */
    if (ostype) free(ostype);
    memset(tmp, 0, 100);
    sprintf(tmp, "%s/image/ostype", vmpath);
    ostype = xs_read(xsh, xth, tmp, &len);

    if (NULL == ostype){
        /* no action */
    }
    else if (fnmatch("*hvm", ostype, 0) == 0){
        ret = 1;
        goto exit;
    }

exit:
    /* cleanup memory here */
    if (tmp) free(tmp);
    if (vmpath) free(vmpath);
    if (ostype) free(ostype);
    if (xsh) xs_daemon_close(xsh);

    return ret;
}

uint32_t xa_get_domain_id (char *name)
{
    char **domains = NULL;
    int size = 0;
    int i = 0;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    uint32_t domain_id = 0;

    xsh = xs_domain_open();
    domains = xs_directory(xsh, xth, "/local/domain", &size);
    for (i = 0; i < size; ++i){
        /* read in name */
        char *tmp = malloc(100);
        char *idStr = domains[i];
        sprintf(tmp, "/local/domain/%s/name", idStr);
        char *nameCandidate = xs_read(xsh, xth, tmp, NULL);

        // if name matches, then return number
        if (strncmp(name, nameCandidate, 100) == 0){
            int idNum = atoi(idStr);
            domain_id = (uint32_t) idNum;
            break;
        }

        /* free memory as we go */
        if (tmp) free(tmp);
        if (nameCandidate) free(nameCandidate);
    }

error_exit:
    if (domains) free(domains);
    if (xsh) xs_daemon_close(xsh);
    return domain_id;
}

#else
char *xa_get_vmpath (int id){return NULL;}
char *xa_get_kernel_name (int id){return NULL;}
int xa_ishvm (int id){return 0;}
uint32_t xa_get_domain_id (char *name){return 0;}
#endif /* ENABLE_XEN */

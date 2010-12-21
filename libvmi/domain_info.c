/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */


#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#ifdef ENABLE_XEN
#include <xs.h>

char *vmi_get_vmpath (int id)
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

char *vmi_get_kernel_name (int id)
{
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *vmpath = NULL;
    char *kernel = NULL;
    char *tmp = NULL;

    vmpath = vmi_get_vmpath(id);

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
int vmi_ishvm (int id)
{
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *vmpath = NULL;
    char *ostype = NULL;
    char *tmp = NULL;
    unsigned int len = 0;
    int ret = 0;

    /* setup initial values */
    vmpath = vmi_get_vmpath(id);
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

uint32_t vmi_get_domain_id (char *name)
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
char *vmi_get_vmpath (int id){return NULL;}
char *vmi_get_kernel_name (int id){return NULL;}
int vmi_ishvm (int id){return 0;}
uint32_t vmi_get_domain_id (char *name){return 0;}
#endif /* ENABLE_XEN */

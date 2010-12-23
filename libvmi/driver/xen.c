/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#ifdef ENABLE_XEN
#include "libvmi.h"
#include "private.h"
#include "driver/xen.h"
#include "driver/interface.h"
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <xs.h>

//----------------------------------------------------------------------------
// Helper functions

char *xen_get_vmpath (unsigned long domainid)
{
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *tmp = NULL;
    char *vmpath = NULL;

    /* get the vm path */
    tmp = safe_malloc(100);
    memset(tmp, 0, 100);
    snprintf(tmp, 100, "/local/domain/%d/vm", domainid);
    xsh = xs_domain_open();
    vmpath = xs_read(xsh, xth, tmp, NULL);

error_exit:
    /* cleanup memory here */
    if (tmp) free(tmp);
    if (xsh) xs_daemon_close(xsh);

    return vmpath;
}

// formerly vmi_get_kernel_name
//char *xen_get_kernel_name (unsigned long domainid)
//{
//    struct xs_handle *xsh = NULL;
//    xs_transaction_t xth = XBT_NULL;
//    char *vmpath = NULL;
//    char *kernel = NULL;
//    char *tmp = NULL;
//
//    vmpath = xen_get_vmpath(domainid);
//
//    /* get the kernel name */
//    tmp = safe_malloc(100);
//    memset(tmp, 0, 100);
//    snprintf(tmp, 100, "%s/image/kernel", vmpath);
//    xsh = xs_domain_open();
//    kernel = xs_read(xsh, xth, tmp, NULL);
//
//error_exit:
//    /* cleanup memory here */
//    if (tmp) free(tmp);
//    if (vmpath) free(vmpath);
//    if (xsh) xs_daemon_close(xsh);
//
//    return kernel;
//}

int xen_ishvm (unsigned long domainid)
{
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *vmpath = NULL;
    char *ostype = NULL;
    char *tmp = NULL;
    unsigned int len = 0;
    int ret = 0;

    /* setup initial values */
    vmpath = xen_get_vmpath(domainid);
    xsh = xs_domain_open();
    tmp = safe_malloc(100);

    /* check the value for xen 3.2.x and earlier */
    memset(tmp, 0, 100);
    snprintf(tmp, 100, "%s/image/kernel", vmpath);
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
    snprintf(tmp, 100, "%s/image/ostype", vmpath);
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

// formerly vmi_get_domain_id
//unsigned long xen_lookup_domainid (char *name)
//{
//    char **domains = NULL;
//    int size = 0;
//    int i = 0;
//    struct xs_handle *xsh = NULL;
//    xs_transaction_t xth = XBT_NULL;
//    unsigned long domainid = 0;
//
//    xsh = xs_domain_open();
//    domains = xs_directory(xsh, xth, "/local/domain", &size);
//    for (i = 0; i < size; ++i){
//        /* read in name */
//        char *tmp = safe_malloc(100);
//        char *idStr = domains[i];
//        snprintf(tmp, 100, "/local/domain/%s/name", idStr);
//        char *nameCandidate = xs_read(xsh, xth, tmp, NULL);
//
//        // if name matches, then return number
//        if (strncmp(name, nameCandidate, 100) == 0){
//            int idNum = atoi(idStr);
//            domainid = (unsigned long) idNum;
//            break;
//        }
//
//        /* free memory as we go */
//        if (tmp) free(tmp);
//        if (nameCandidate) free(nameCandidate);
//    }
//
//error_exit:
//    if (domains) free(domains);
//    if (xsh) xs_daemon_close(xsh);
//    return domainid;
//}

//----------------------------------------------------------------------------
// Xen-Specific Interface Functions (no direction mapping to driver_*)

xen_instance_t xen_get_instance(vmi_instance_t vmi)
{
    xen_instance_t xeninst = (xen_instance_t) vmi->driver;
    return xeninst;
}

unsigned long xen_get_domainid (vmi_instance_t vmi)
{
    return xen_get_instance(vmi).domainid;
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

void xen_set_domainid (vmi_instance_t vmi, unsigned long domainid)
{
    xen_get_instance().domainid = domainid;
}

status_t xen_init (vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;
    int xc_handle;

    /* open handle to the libxc interface */
    if ((xc_handle = xc_interface_open()) == -1){
        errprint("Failed to open libxc interface.\n");
        goto error_exit;
    }
    xen_get_instance().xc_handle = xc_handle;

    /* initialize other xen-specific values */
    xen_get_instance().live_pfn_to_mfn_table = NULL;
    xen_get_instance().nr_pfns = 0;

    /* setup the info struct */
    if (xc_domain_getinfo(xc_handle, xen_get_domainid(vmi), 1, &(xen_get_instance().info)) != 1){
        errprint("Failed to get domain info for Xen.\n");
        ret = vmi_report_error(vmi, 0, VMI_ECRITICAL);
        if (VMI_FAILURE == ret) goto error_exit;
    }

    /* determine if target is hvm or pv */
    xen_get_instance().hvm = xen_ishvm(xen_get_domainid(vmi));
#ifdef VMI_DEBUG
    if (xen_get_instance().hvm){
        dbprint("**set hvm to true (HVM).\n");
    }
    else{
        dbprint("**set hvm to false (PV).\n");
    }
#endif /* VMI_DEBUG */

    ret = VMI_SUCCESS;

error_exit:
    return ret;
}

void xen_destroy (vmi_instance_t vmi)
{
    if (xen_get_instance().live_pfn_to_mfn_table){
        munmap(xen_get_instance().live_pfn_to_mfn_table, xen_get_instance().nr_pfns * 4);
    }

    get_xen_instance().domainid = 0;
    xc_interface_close(get_xen_instance().xc_handle);
}

status_t xen_get_domainname (vmi_instance_t vmi, char **name)
{
    status_t ret = VMI_FAILURE;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *tmp = safe_malloc(100);

    memset(tmp, 0, 100);
    snprintf(tmp, 100, "/local/domain/%d/name", xen_get_domainid(vmi));
    xsh = xs_domain_open();
    *name = xs_read(xsh, xth, tmp, NULL);
    if (NULL == name){
        errprint("domain id %d is not running\n", xen_get_domainid(instance));
        goto error_exit;
    }
    ret = VMI_SUCCESS;

error_exit:
    return ret;
}

status_t xen_get_memsize (vmi_instance_t vmi, unsigned long *size)
{
    status_t ret = VMI_FAILURE;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;

    char *tmp = safe_malloc(100);
    memset(tmp, 0, 100);

    /* get the memory size from the xenstore */
    snprintf(tmp, 100, "/local/domain/%d/memory/target", xen_get_domainid(vmi));
    xsh = xs_domain_open();
    *size = strtol(xs_read(xsh, xth, tmp, NULL), NULL, 10) * 1024;
    if (!size){
        errprint("failed to get memory size for Xen domain.\n");
        goto error_exit;
    }
    ret = VMI_SUCCESS;

error_exit:
    if (xsh) xs_daemon_close(xsh);
    return ret;
}

status_t xen_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    status_t ret = VMI_SUCCESS;
#ifdef HAVE_CONTEXT_ANY
    vcpu_guest_context_any_t ctxt_any;
#endif /* HAVE_CONTEXT_ANY */
    vcpu_guest_context_t ctxt;

#ifdef HAVE_CONTEXT_ANY
    if ((ret = xc_vcpu_getcontext(
                xen_get_instance(vmi).xc_handle,
                xen_get_domainid(vmi),
                vcpu,
                &ctxt_any)) != 0){
#else
    if ((ret = xc_vcpu_getcontext(
                xen_get_instance(vmi).xc_handle,
                xen_get_domainid(vmi),
                vcpu,
                &ctxt)) != 0){
#endif /* HAVE_CONTEXT_ANY */
        errprint("Failed to get context information.\n");
        ret = VMI_FAILURE;
        goto error_exit;
    }

#ifdef HAVE_CONTEXT_ANY
    ctxt = ctxt_any.c;
#endif /* HAVE_CONTEXT_ANY */

    switch (reg){
        case REG_CR0:
            *value = ctxt.ctrlreg[0];
            break;
        case REG_CR1:
            *value = ctxt.ctrlreg[1];
            break;
        case REG_CR2:
            *value = ctxt.ctrlreg[2];
            break;
        case REG_CR3:
            *value = ctxt.ctrlreg[3];
            break;
        case REG_CR4:
            *value = ctxt.ctrlreg[4];
            break;
        default:
            ret = VMI_FAILURE;
            break;
    }

error_exit:
    return ret;
}

//////////////////////////////////////////////////////////////////////////////
#else

status_t xen_init (vmi_instance_t vmi) { return VMI_FAILURE; }
void xen_destroy (vmi_instance_t vmi) { return; }
unsigned long xen_get_domainid (vmi_instance_t vmi) { return 0; }
void xen_set_domainid (vmi_instance_t vmi, unsigned long domainid) { return; }
status_t xen_get_domainname (vmi_instance_t vmi, char **name) { return VMI_FAILURE; }
status_t xen_get_memsize (vmi_instance_t vmi, unsigned long *size) { return VMI_FAILURE; }
status_t xen_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu) { return VMI_FAILURE; }

#endif /* ENABLE_XEN */

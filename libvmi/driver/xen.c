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
#include "driver/xen.h"
#include "driver/interface.h"

#if ENABLE_XEN == 1
#define _GNU_SOURCE
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <xs.h>

//----------------------------------------------------------------------------
// Helper functions

static char *xen_get_vmpath (unsigned long domainid)
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

static int xen_ishvm (unsigned long domainid)
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


//----------------------------------------------------------------------------
// Xen-Specific Interface Functions (no direct mapping to driver_*)

static xen_instance_t *xen_get_instance (vmi_instance_t vmi)
{
    return ((xen_instance_t *)vmi->driver);
}

static unsigned long xen_get_xchandle (vmi_instance_t vmi)
{
    return xen_get_instance(vmi)->xchandle;
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

// formerly vmi_get_domain_id
unsigned long xen_get_domainid_from_name (vmi_instance_t vmi, char *name)
{
    char **domains = NULL;
    int size = 0;
    int i = 0;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    unsigned long domainid = 0;

    xsh = xs_domain_open();
    domains = xs_directory(xsh, xth, "/local/domain", &size);
    for (i = 0; i < size; ++i){
        /* read in name */
        char *tmp = safe_malloc(100);
        char *idStr = domains[i];
        snprintf(tmp, 100, "/local/domain/%s/name", idStr);
        char *nameCandidate = xs_read(xsh, xth, tmp, NULL);

        // if name matches, then return number
        if (strncmp(name, nameCandidate, 100) == 0){
            int idNum = atoi(idStr);
            domainid = (unsigned long) idNum;
            break;
        }

        /* free memory as we go */
        if (tmp) free(tmp);
        if (nameCandidate) free(nameCandidate);
    }

error_exit:
    if (domains) free(domains);
    if (xsh) xs_daemon_close(xsh);
    return domainid;
}

unsigned long xen_get_domainid (vmi_instance_t vmi)
{
    return xen_get_instance(vmi)->domainid;
}

void xen_set_domainid (vmi_instance_t vmi, unsigned long domainid)
{
    xen_get_instance(vmi)->domainid = domainid;
}

status_t xen_init (vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;
    int xchandle;

    /* open handle to the libxc interface */
    if ((xchandle = xc_interface_open()) == -1){
        errprint("Failed to open libxc interface.\n");
        goto error_exit;
    }
    xen_get_instance(vmi)->xchandle = xchandle;

    /* initialize other xen-specific values */
    xen_get_instance(vmi)->live_pfn_to_mfn_table = NULL;
    xen_get_instance(vmi)->nr_pfns = 0;

    /* setup the info struct */
    if (xc_domain_getinfo(xchandle, xen_get_domainid(vmi), 1, &(xen_get_instance(vmi)->info)) != 1){
        errprint("Failed to get domain info for Xen.\n");
        goto error_exit;
    }

    /* determine if target is hvm or pv */
    xen_get_instance(vmi)->hvm = xen_ishvm(xen_get_domainid(vmi));
#ifdef VMI_DEBUG
    if (xen_get_instance(vmi)->hvm){
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
    if (xen_get_instance(vmi)->live_pfn_to_mfn_table){
        munmap(xen_get_instance(vmi)->live_pfn_to_mfn_table, xen_get_instance(vmi)->nr_pfns * 4);
    }

    xen_get_instance(vmi)->domainid = 0;
    xc_interface_close(xen_get_xchandle(vmi));
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
        errprint("Domain ID %d is not running.\n", xen_get_domainid(vmi));
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
                xen_get_xchandle(vmi),
                xen_get_domainid(vmi),
                vcpu,
                &ctxt_any)) != 0){
#else
    if ((ret = xc_vcpu_getcontext(
                xen_get_xchandle(vmi),
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
        case CR0:
            *value = ctxt.ctrlreg[0];
            break;
        case CR1:
            *value = ctxt.ctrlreg[1];
            break;
        case CR2:
            *value = ctxt.ctrlreg[2];
            break;
        case CR3:
            *value = ctxt.ctrlreg[3];
            break;
        case CR4:
            *value = ctxt.ctrlreg[4];
            break;
        default:
            ret = VMI_FAILURE;
            break;
    }

error_exit:
    return ret;
}

unsigned long xen_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn)
{
    shared_info_t *live_shinfo = NULL;
    unsigned long *live_pfn_to_mfn_frame_list_list = NULL;
    unsigned long *live_pfn_to_mfn_frame_list = NULL;

    /* Live mapping of the table mapping each PFN to its current MFN. */
    unsigned long *live_pfn_to_mfn_table = NULL;
    unsigned long nr_pfns = 0;
    unsigned long ret = 0;

    if (xen_get_instance(vmi)->hvm){
        return pfn;
    }

    if (NULL == xen_get_instance(vmi)->live_pfn_to_mfn_table){
        live_shinfo = vmi_mmap_mfn(vmi, PROT_READ, xen_get_instance(vmi)->info.shared_info_frame);
        if (live_shinfo == NULL){
            errprint("Failed to init live_shinfo.\n");
            goto error_exit;
        }
        nr_pfns = live_shinfo->arch.max_pfn;

        live_pfn_to_mfn_frame_list_list = vmi_mmap_mfn(vmi, PROT_READ, live_shinfo->arch.pfn_to_mfn_frame_list_list);
        if (live_pfn_to_mfn_frame_list_list == NULL){
            errprint("Failed to init live_pfn_to_mfn_frame_list_list.\n");
            goto error_exit;
        }

        live_pfn_to_mfn_frame_list = xc_map_foreign_batch(
            xen_get_xchandle(vmi),
            xen_get_domainid(vmi),
            PROT_READ,
            live_pfn_to_mfn_frame_list_list,
            (nr_pfns+(fpp*fpp)-1)/(fpp*fpp) );
        if (live_pfn_to_mfn_frame_list == NULL){
            errprint("Failed to init live_pfn_to_mfn_frame_list.\n");
            goto error_exit;
        }
        live_pfn_to_mfn_table = xc_map_foreign_batch(
            xen_get_xchandle(vmi),
            xen_get_domainid(vmi),
            PROT_READ,
            live_pfn_to_mfn_frame_list, (nr_pfns+fpp-1)/fpp );
        if (live_pfn_to_mfn_table  == NULL){
            errprint("Failed to init live_pfn_to_mfn_table.\n");
            goto error_exit;
        }

        /* save mappings for later use */
        xen_get_instance(vmi)->live_pfn_to_mfn_table = live_pfn_to_mfn_table;
        xen_get_instance(vmi)->nr_pfns = nr_pfns;
    }

    ret = xen_get_instance(vmi)->live_pfn_to_mfn_table[pfn];

error_exit:
    if (live_shinfo) munmap(live_shinfo, XC_PAGE_SIZE);
    if (live_pfn_to_mfn_frame_list_list)
        munmap(live_pfn_to_mfn_frame_list_list, XC_PAGE_SIZE);
    if (live_pfn_to_mfn_frame_list)
        munmap(live_pfn_to_mfn_frame_list, XC_PAGE_SIZE);

    return ret;
}

void *xen_map_page (vmi_instance_t vmi, int prot, unsigned long page)
{
    return xc_map_foreign_range(xen_get_xchandle(vmi), xen_get_domainid(vmi), 1, prot, page);
}

int xen_is_pv (vmi_instance_t vmi)
{
    return !xen_get_instance(vmi)->hvm;
}

status_t xen_test (unsigned long id, char *name)
{
    status_t ret = VMI_FAILURE;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *tmp = NULL;

    xsh = xs_domain_open();
    if (NULL == xsh){
        goto error_exit;
    }
    tmp = xs_read(xsh, xth, "/local/domain/0/name", NULL);
    if (NULL == tmp){
        goto error_exit;
    }
    free(tmp);
    ret = VMI_SUCCESS;

error_exit:
    return ret;
}

//////////////////////////////////////////////////////////////////////////////
#else

status_t xen_init (vmi_instance_t vmi) { return VMI_FAILURE; }
void xen_destroy (vmi_instance_t vmi) { return; }
unsigned long xen_get_domainid_from_name (vmi_instance_t vmi, char *name) { return 0; }
unsigned long xen_get_domainid (vmi_instance_t vmi) { return 0; }
void xen_set_domainid (vmi_instance_t vmi, unsigned long domainid) { return; }
status_t xen_get_domainname (vmi_instance_t vmi, char **name) { return VMI_FAILURE; }
status_t xen_get_memsize (vmi_instance_t vmi, unsigned long *size) { return VMI_FAILURE; }
status_t xen_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu) { return VMI_FAILURE; }
unsigned long xen_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn) { return 0; }
void *xen_map_page (vmi_instance_t vmi, int prot, unsigned long page) { return NULL; }
void *xen_map_pages (vmi_instance_t vmi, int prot, unsigned long *pages, unsigned long num_pages) { return NULL; }
int xen_is_pv (vmi_instance_t vmi) { return 0; }
status_t xen_test (unsigned long id, char *name) { return VMI_FAILURE; }

#endif /* ENABLE_XEN */

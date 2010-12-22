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
#include <xs.h>

xen_instance_t xen_get_instance(vmi_instance_t vmi)
{
    xen_instance_t xeninst = (xen_instance_t) vmi->driver;
    return xeninst;
}

unsigned long xen_get_domainid (vmi_instance_t vmi)
{
    return xen_get_instance(vmi).domainid;
}

status_t xen_set_memsize (vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;
    unsigned long size = 0;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;

    /* validate the domainid */
    int domainid = xen_get_domainid();
    if (!domainid){
        fprintf(stderr, "ERROR: bad domain id in xen_get_memsize\n");
        goto error_exit;
    }

    /* validate the malloc */
    char *tmp = malloc(100);
    if (NULL == tmp){
        fprintf(stderr, "ERROR: failed to allocate memory for tmp variable\n");
        goto error_exit;
    }
    memset(tmp, 0, 100);

    /* get the memory size from the xenstore */
    snprintf(tmp, 100, "/local/domain/%d/memory/target", domainid);
    xsh = xs_domain_open();
    size = strtol(xs_read(xsh, xth, tmp, NULL), NULL, 10) * 1024;
    if (!size){
        fprintf(stderr, "ERROR: failed to get memory size for Xen domain.\n");
        goto error_exit;
    }
    xen_get_instance(vmi).size = size;
    dbprint("**set instance->driver.size = %d\n", size);
    ret = VMI_SUCCESS;

error_exit:
    if (xsh) xs_daemon_close(xsh);
    return ret;
}

//////////////////////////////////////////////////////////////////////
#else

unsigned long xen_get_domainid (vmi_instance_t vmi) { return 0; }
status_t xen_set_memsize (vmi_instance_t vmi) { return VMI_FAILURE; }

#endif /* ENABLE_XEN */

/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#ifdef ENABLE_XEN
#include <xs.h>

unsigned long xen_get_domainid ()
{
    return 1; //TODO fix this to actually work!
}

unsigned long xen_get_memsize ()
{
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
    dbprint("**set instance->m.xen.size = %d\n", instance->m.xen.size);

error_exit:
    if (xsh) xs_daemon_close(xsh);
    return size;
}

//////////////////////////////////////////////////////////////////////
#else

unsigned long xen_get_domainid () { return 0; };
unsigned long xen_get_memsize () { return 0; };

#endif /* ENABLE_XEN */

/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#ifdef ENABLE_XEN
#include <xenctrl.h>

typedef struct xen_instance{
    int xc_handle;          /**< handle to xenctrl library (libxc) */
    unsigned long domainid; /**< domid that we are accessing */
    int xen_version;        /**< version of Xen libxa is running on */
    xc_dominfo_t info;      /**< libxc info: domid, ssidref, stats, etc */
    uint32_t size;          /**< total size of domain's memory */
    unsigned long *live_pfn_to_mfn_table;
    unsigned long nr_pfns;
} xen_instance_t;

#endif /* ENABLE_XEN */

unsigned long xen_get_domainid (vmi_instance_t vmi);
status_t xen_set_memsize (vmi_instance_t vmi);

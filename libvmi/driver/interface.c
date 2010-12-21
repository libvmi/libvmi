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

#include <stdlib.h>

struct driver_instance{
    unsigned long (*get_vmid_ptr)();
    unsigned long (*get_memsize_ptr)();
};
typedef struct driver_instance * driver_instance_t;

driver_instance_t instance = NULL;

driver_instance_t driver_get_instance (vmi_instance_t vmi)
{
    if (NULL != instance){
        return instance;
    }
    else{
        /* allocate memory for the function pointers */
        instance = (driver_instance_t) malloc(sizeof(struct driver_instance));
        if (NULL == instance){
            return NULL;
        }

        /* assign the function pointers */
        if (VMI_MODE_XEN == vmi->mode){
            instance->get_vmid_ptr = &xen_get_domainid;
            instance->get_memsize_ptr = &xen_get_memsize;
        }
        else if (VMI_MODE_KVM == vmi->mode){
        }
        else if (VMI_MODE_FILE == vmi->mode){
        }
    }
}

unsigned long driver_get_vmid (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs){
        return ptrs->get_vmid_ptr();
    }
    else{
        return 0;
    }
}

unsigned long driver_get_memsize (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs){
        return ptrs->get_memsize_ptr();
    }
    else{
        return 0;
    }
}




// lookup domain name from id // xen, used in read_config_file from core.c
// lookup domain id from name // xen, used in init_name functions
// get id of current target VM
// get name of current target VM

// lookup vcpu context // xen, used in get_page_info_xen from core.c to get control regs
// lookup current cr3 value

// lookup vmm version // xen, to ensure that we support the target version and do tweeks to handle version differences

// get handle to vmm and/or control library // could be held as an internal private state to the driver

// see if the VM is HVM or PV // xen only, but others could just return HVM

// cleanup function // called from helper_destroy

//---> xen specific stuff in domain_info.c

// pfn -> mfn conversion

// map a single page

// map multiple (possible non-contiguous) pages // used in xa_access_user_va_range

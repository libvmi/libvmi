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
#include "driver/file.h"
#include <stdlib.h>

struct driver_instance{
    status_t (*init_ptr)(vmi_instance_t);
    void (*destroy_ptr)(vmi_instance_t);
    unsigned long (*get_id_ptr)(vmi_instance_t);
    void (*set_id_ptr)(vmi_instance_t, unsigned long);
    status_t (*get_name_ptr)(vmi_instance_t, char **);
    void (*set_name_ptr)(vmi_instance_t, char *);
    status_t (*get_memsize_ptr)(vmi_instance_t, unsigned long *);
    status_t (*get_vcpureg_ptr)(vmi_instance_t, reg_t *, registers_t, unsigned long);
};
typedef struct driver_instance * driver_instance_t;

driver_instance_t instance = NULL;
xen_instance_t xeninst;
file_instance_t fileinst;

driver_instance_t driver_get_instance (vmi_instance_t vmi)
{
    if (NULL != instance){
        return instance;
    }
    else{
        /* allocate memory for the function pointers */
        instance = (driver_instance_t) safe_malloc(sizeof(struct driver_instance));

        /* assign the function pointers */
        if (VMI_MODE_XEN == vmi->mode){
            instance->driver = &xeninst;
            instance->init_ptr = &xen_init;
            instance->destroy_ptr = &xen_destroy;
            instance->get_id_ptr = &xen_get_domainid;
            instance->set_id_ptr = &xen_set_domainid;
            instance->get_name_ptr = &xen_get_domainname;
            //TODO add set_name_ptr
            instance->get_memsize_ptr = &xen_get_memsize;
            instance->get_vcpureg_ptr = &xen_get_vcpureg;
        }
        else if (VMI_MODE_KVM == vmi->mode){
        }
        else if (VMI_MODE_FILE == vmi->mode){
            instance->driver = &fileinst;
            instance->init_ptr = &file_init;
            instance->set_name_ptr = &file_set_name;
            instance->get_memsize_ptr = &file_get_memsize;
        }
    }
}

status_t driver_init (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs){
        return ptrs->init_ptr(vmi);
    }
    else{
        return VMI_FAILURE;
    }
}

void driver_destroy (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs){
        return ptrs->destroy_ptr(vmi);
    }
    else{
        return;
    }
}

unsigned long driver_get_id (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs){
        return ptrs->get_id_ptr(vmi);
    }
    else{
        return 0;
    }
}

void driver_set_id (vmi_instance_t vmi, unsigned long id);
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs){
        return ptrs->set_id_ptr(vmi, id);
    }
    else{
        return;
    }
}

status_t driver_get_name (vmi_instance_t vmi, char **name)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs){
        return ptrs->get_vmname_ptr(vmi, name);
    }
    else{
        return VMI_FAILURE;
    }
}

void driver_set_name (vmi_instance_t vmi, char *name);
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs){
        return ptrs->set_name_ptr(vmi, name);
    }
    else{
        return;
    }
}

status_t driver_get_memsize (vmi_instance_t vmi, unsigned long *size)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs){
        return ptrs->get_memsize_ptr(vmi, size);
    }
    else{
        return VMI_FAILURE;
    }
}

status_t driver_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs){
        return ptrs->get_vcpureg_ptr(vmi, value, reg, vcpu);
    }
    else{
        return VMI_FAILURE;
    }
}





// lookup domain name from id // xen, used in read_config_file from core.c
// lookup domain id from name // xen, used in init_name functions

// pfn -> mfn conversion

// map a single page

// map multiple (possible non-contiguous) pages // used in xa_access_user_va_range

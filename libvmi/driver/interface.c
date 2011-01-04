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
    unsigned long (*pfn_to_mfn_ptr)(vmi_instance_t, unsigned long);
    void *(*map_page_ptr)(vmi_instance_t, int, unsigned long);
    void *(*map_pages_ptr)(vmi_instance_t, int, unsigned long *, unsigned long);
    int (*is_pv_ptr)(vmi_instance_t);
};
typedef struct driver_instance * driver_instance_t;

driver_instance_t instance = NULL;
xen_instance_t xeninst;
file_instance_t fileinst;

void driver_xen_setup (vmi_instance_t vmi)
{
    vmi->driver = &xeninst;
    instance->init_ptr = &xen_init;
    instance->destroy_ptr = &xen_destroy;
    instance->get_id_ptr = &xen_get_domainid;
    instance->set_id_ptr = &xen_set_domainid;
    instance->get_name_ptr = &xen_get_domainname;
    //TODO add set_name_ptr
    instance->get_memsize_ptr = &xen_get_memsize;
    instance->get_vcpureg_ptr = &xen_get_vcpureg;
    instance->pfn_to_mfn_ptr = &xen_pfn_to_mfn;
    instance->map_page_ptr = &xen_map_page;
    instance->map_pages_ptr = &xen_map_pages;
    instance->is_pv_ptr = &xen_is_pv;
}

void driver_kvm_setup (vmi_instance_t vmi)
{
    //TODO set vmi->driver
    //TODO add init_ptr
    //TODO add destroy_ptr
    //TODO add get_id_ptr
    //TODO add set_id_ptr
    //TODO add get_name_ptr
    //TODO add set_name_ptr
    //TODO add get_memsize_ptr
    //TODO add get_vcpureg_ptr
    //TODO add pfn_to_mfn_ptr
    //TODO add map_page_ptr
    //TODO add map_pages_ptr
    //TODO add is_pv_ptr
}

void driver_file_setup (vmi_instance_t vmi)
{
    vmi->driver = &fileinst;
    instance->init_ptr = &file_init;
    //TODO add destroy_ptr
    //TODO add get_id_ptr
    //TODO add set_id_ptr
    //TODO add get_name_ptr
    instance->set_name_ptr = &file_set_name;
    instance->get_memsize_ptr = &file_get_memsize;
    instance->get_vcpureg_ptr = &file_get_vcpureg;
    instance->pfn_to_mfn_ptr = &file_pfn_to_mfn;
    instance->map_page_ptr = &file_map_page;
    //TODO add map_pages_ptr
    instance->is_pv_ptr = &file_is_pv;
}

driver_instance_t driver_get_instance (vmi_instance_t vmi)
{
    if (NULL == instance){
        /* allocate memory for the function pointers */
        instance = (driver_instance_t) safe_malloc(sizeof(struct driver_instance));

        /* assign the function pointers */
        if (VMI_MODE_XEN == vmi->mode){
            driver_xen_setup(vmi);
        }
        else if (VMI_MODE_KVM == vmi->mode){
            driver_kvm_setup(vmi);
        }
        else if (VMI_MODE_FILE == vmi->mode){
            driver_file_setup(vmi);
        }

    }
    return instance;
}

status_t driver_init (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->init_ptr){
        return ptrs->init_ptr(vmi);
    }
    else{
        return VMI_FAILURE;
    }
}

void driver_destroy (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->destroy_ptr){
        return ptrs->destroy_ptr(vmi);
    }
    else{
        return;
    }
}

unsigned long driver_get_id (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->get_id_ptr){
        return ptrs->get_id_ptr(vmi);
    }
    else{
        return 0;
    }
}

void driver_set_id (vmi_instance_t vmi, unsigned long id)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->set_id_ptr){
        return ptrs->set_id_ptr(vmi, id);
    }
    else{
        return;
    }
}

status_t driver_get_name (vmi_instance_t vmi, char **name)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->get_name_ptr){
        return ptrs->get_name_ptr(vmi, name);
    }
    else{
        return VMI_FAILURE;
    }
}

void driver_set_name (vmi_instance_t vmi, char *name)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->set_name_ptr){
        return ptrs->set_name_ptr(vmi, name);
    }
    else{
        return;
    }
}

status_t driver_get_memsize (vmi_instance_t vmi, unsigned long *size)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->get_memsize_ptr){
        return ptrs->get_memsize_ptr(vmi, size);
    }
    else{
        return VMI_FAILURE;
    }
}

status_t driver_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->get_vcpureg_ptr){
        return ptrs->get_vcpureg_ptr(vmi, value, reg, vcpu);
    }
    else{
        return VMI_FAILURE;
    }
}

unsigned long driver_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->pfn_to_mfn_ptr){
        return ptrs->pfn_to_mfn_ptr(vmi, pfn);
    }
    else{
        return 0;
    }
}

void *driver_map_page (vmi_instance_t vmi, int prot, unsigned long page)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->map_page_ptr){
        return ptrs->map_page_ptr(vmi, prot, page);
    }
    else{
        return NULL;
    }
}

void *driver_map_pages (vmi_instance_t vmi, int prot, unsigned long *pages, unsigned long num_pages)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->map_pages_ptr){
        return ptrs->map_pages_ptr(vmi, prot, pages, num_pages);
    }
    else{
        return NULL;
    }
}

int driver_is_pv (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->is_pv_ptr){
        return ptrs->is_pv_ptr(vmi);
    }
    else{
        return 0;
    }
}

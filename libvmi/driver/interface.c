/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "libvmi.h"
#include "private.h"
#include "driver/xen.h"
#include "driver/kvm.h"
#include "driver/file.h"
#include <stdlib.h>

struct driver_instance{
    status_t (*init_ptr)(vmi_instance_t);
    void (*destroy_ptr)(vmi_instance_t);
    unsigned long (*get_id_from_name_ptr)(vmi_instance_t, char *);
    unsigned long (*get_id_ptr)(vmi_instance_t);
    void (*set_id_ptr)(vmi_instance_t, unsigned long);
    status_t (*get_name_ptr)(vmi_instance_t, char **);
    void (*set_name_ptr)(vmi_instance_t, char *);
    status_t (*get_memsize_ptr)(vmi_instance_t, unsigned long *);
    status_t (*get_vcpureg_ptr)(vmi_instance_t, reg_t *, registers_t, unsigned long);
    unsigned long (*pfn_to_mfn_ptr)(vmi_instance_t, unsigned long);
    void *(*read_page_ptr)(vmi_instance_t, unsigned long);
    status_t (*write_ptr)(vmi_instance_t, addr_t, void *, uint32_t);
    int (*is_pv_ptr)(vmi_instance_t);
    status_t (*pause_vm_ptr)(vmi_instance_t);
    status_t (*resume_vm_ptr)(vmi_instance_t);
};
typedef struct driver_instance * driver_instance_t;

static driver_instance_t instance = NULL;
static xen_instance_t xeninst;
static kvm_instance_t kvminst;
static file_instance_t fileinst;

static void driver_xen_setup (vmi_instance_t vmi)
{
    vmi->driver = &xeninst;
    instance->init_ptr = &xen_init;
    instance->destroy_ptr = &xen_destroy;
    instance->get_id_from_name_ptr = &xen_get_domainid_from_name;
    instance->get_id_ptr = &xen_get_domainid;
    instance->set_id_ptr = &xen_set_domainid;
    instance->get_name_ptr = &xen_get_domainname;
    instance->set_name_ptr = &xen_set_domainname;
    instance->get_memsize_ptr = &xen_get_memsize;
    instance->get_vcpureg_ptr = &xen_get_vcpureg;
    instance->pfn_to_mfn_ptr = &xen_pfn_to_mfn;
    instance->read_page_ptr = &xen_read_page;
    instance->write_ptr = &xen_write;
    instance->is_pv_ptr = &xen_is_pv;
    instance->pause_vm_ptr = &xen_pause_vm;
    instance->resume_vm_ptr = &xen_resume_vm;
}

static void driver_kvm_setup (vmi_instance_t vmi)
{
    vmi->driver = &kvminst;
    instance->init_ptr = &kvm_init;
    instance->destroy_ptr = &kvm_destroy;
    instance->get_id_from_name_ptr = &kvm_get_id_from_name;
    instance->get_id_ptr = &kvm_get_id;
    instance->set_id_ptr = &kvm_set_id;
    instance->get_name_ptr = &kvm_get_name;
    instance->set_name_ptr = &kvm_set_name;
    instance->get_memsize_ptr = &kvm_get_memsize;
    instance->get_vcpureg_ptr = &kvm_get_vcpureg;
    instance->pfn_to_mfn_ptr = &kvm_pfn_to_mfn;
    instance->read_page_ptr = &kvm_read_page;
    instance->write_ptr = &kvm_write;
    instance->is_pv_ptr = &kvm_is_pv;
    instance->pause_vm_ptr = &kvm_pause_vm;
    instance->resume_vm_ptr = &kvm_resume_vm;
}

static void driver_file_setup (vmi_instance_t vmi)
{
    vmi->driver = &fileinst;
    instance->init_ptr = &file_init;
    instance->destroy_ptr = &file_destroy;
    instance->get_id_from_name_ptr = NULL; //TODO add get_id_from_name_ptr
    instance->get_id_ptr = NULL; //TODO add get_id_ptr
    instance->set_id_ptr = NULL; //TODO add set_id_ptr
    instance->get_name_ptr = NULL; //TODO add get_name_ptr
    instance->set_name_ptr = &file_set_name;
    instance->get_memsize_ptr = &file_get_memsize;
    instance->get_vcpureg_ptr = &file_get_vcpureg;
    instance->pfn_to_mfn_ptr = &file_pfn_to_mfn;
    instance->read_page_ptr = &file_read_page;
    instance->write_ptr = &file_write;
    instance->is_pv_ptr = &file_is_pv;
    instance->pause_vm_ptr = &file_pause_vm;
    instance->resume_vm_ptr = &file_resume_vm;
}

static void driver_null_setup (vmi_instance_t vmi)
{
    vmi->driver = NULL;
    instance->init_ptr = NULL;
    instance->destroy_ptr = NULL;
    instance->get_id_from_name_ptr = NULL;
    instance->get_id_ptr = NULL;
    instance->set_id_ptr = NULL;
    instance->get_name_ptr = NULL;
    instance->set_name_ptr = NULL;
    instance->get_memsize_ptr = NULL;
    instance->get_vcpureg_ptr = NULL;
    instance->pfn_to_mfn_ptr = NULL;
    instance->read_page_ptr = NULL;
    instance->is_pv_ptr = NULL;
    instance->pause_vm_ptr = NULL;
    instance->resume_vm_ptr = NULL;
}

static driver_instance_t driver_get_instance (vmi_instance_t vmi)
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
        else{
            driver_null_setup(vmi);
        }

    }
    return instance;
}

status_t driver_init_mode (vmi_instance_t vmi, unsigned long id, char *name)
{
    unsigned long count = 0;

    /* see what systems are accessable */
    if (VMI_SUCCESS == xen_test(id, name)){
        dbprint("--found Xen\n");
        vmi->mode = VMI_MODE_XEN;
        count++;
    }
    if (VMI_SUCCESS == kvm_test(id, name)){
        dbprint("--found KVM\n");
        vmi->mode = VMI_MODE_KVM;
        count++;
    }
    if (VMI_SUCCESS == file_test(id, name)){
        dbprint("--found file\n");
        vmi->mode = VMI_MODE_FILE;
        count++;
    }

    /* if we didn't see exactly one system, report error */
    if (count == 0){
        errprint("Could not find a VMM or file to use.\n");
        return VMI_FAILURE;
    }
    else if (count > 1){
        errprint("Found more than one VMM of file to use,\nplease specify what you want instead of using VMI_MODE_AUTO.\n");
        return VMI_FAILURE;
    }
    else{ // count == 1
        return VMI_SUCCESS;
    }
}

status_t driver_init (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->init_ptr){
        return ptrs->init_ptr(vmi);
    }
    else{
        dbprint("WARNING: driver_init function not implemented.\n");
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
        dbprint("WARNING: driver_destroy function not implemented.\n");
        return;
    }
}

unsigned long driver_get_id_from_name (vmi_instance_t vmi, char *name)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->get_id_from_name_ptr){
        return ptrs->get_id_from_name_ptr(vmi, name);
    }
    else{
        dbprint("WARNING: driver_get_id_from_name function not implemented.\n");
        return 0;
    }
}

unsigned long driver_get_id (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->get_id_ptr){
        return ptrs->get_id_ptr(vmi);
    }
    else{
        dbprint("WARNING: driver_get_id function not implemented.\n");
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
        dbprint("WARNING: driver_set_id function not implemented.\n");
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
        dbprint("WARNING: driver_get_name function not implemented.\n");
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
        dbprint("WARNING: driver_set_name function not implemented.\n");
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
        dbprint("WARNING: driver_get_memsize function not implemented.\n");
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
        dbprint("WARNING: driver_get_vcpureg function not implemented.\n");
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
        dbprint("WARNING: driver_pfn_to_mfn function not implemented.\n");
        return 0;
    }
}

void *driver_read_page (vmi_instance_t vmi, unsigned long page)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->read_page_ptr){
        return ptrs->read_page_ptr(vmi, page);
    }
    else{
        dbprint("WARNING: driver_read_page function not implemented.\n");
        return NULL;
    }
}

status_t driver_write (vmi_instance_t vmi, addr_t paddr, void *buf, uint32_t length)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->write_ptr){
        return ptrs->write_ptr(vmi, paddr, buf, length);
    }
    else{
        dbprint("WARNING: driver_write function not implemented.\n");
        return VMI_FAILURE;
    }
}

int driver_is_pv (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->is_pv_ptr){
        return ptrs->is_pv_ptr(vmi);
    }
    else{
        dbprint("WARNING: driver_is_pv function not implemented.\n");
        return 0;
    }
}

status_t driver_pause_vm (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->pause_vm_ptr){
        return ptrs->pause_vm_ptr(vmi);
    }
    else{
        dbprint("WARNING: driver_pause_vm function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t driver_resume_vm (vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->resume_vm_ptr){
        return ptrs->resume_vm_ptr(vmi);
    }
    else{
        dbprint("WARNING: driver_resume_vm function not implemented.\n");
        return VMI_FAILURE;
    }
}

/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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
#include <string.h>

struct driver_instance {
    status_t (
    *init_ptr) (
    vmi_instance_t);
    void (
    *destroy_ptr) (
    vmi_instance_t);
    unsigned long (
    *get_id_from_name_ptr) (
    vmi_instance_t,
    char *);
    status_t (
    *get_name_from_id_ptr) (
    vmi_instance_t,
    unsigned long,
    char **);
    unsigned long (
    *get_id_ptr) (
    vmi_instance_t);
    void (
    *set_id_ptr) (
    vmi_instance_t,
    unsigned long);
    status_t (
    *check_id_ptr) (
    vmi_instance_t,
    unsigned long);
    status_t (
    *get_name_ptr) (
    vmi_instance_t,
    char **);
    void (
    *set_name_ptr) (
    vmi_instance_t,
    char *);
    status_t (
    *get_memsize_ptr) (
    vmi_instance_t,
    uint64_t *);
    status_t (
    *get_vcpureg_ptr) (
    vmi_instance_t,
    reg_t *,
    registers_t,
    unsigned long);
    status_t(
    *set_vcpureg_ptr) (
    vmi_instance_t,
    reg_t,
    registers_t,
    unsigned long);
    status_t (
    *get_address_width_ptr) (
    vmi_instance_t vmi,
    uint8_t * width);
    void *(
    *read_page_ptr) (
    vmi_instance_t,
    addr_t);
    status_t (
    *write_ptr) (
    vmi_instance_t,
    addr_t,
    void *,
    uint32_t);
    int (
    *is_pv_ptr) (
    vmi_instance_t);
    status_t (
    *pause_vm_ptr) (
    vmi_instance_t);
    status_t (
    *resume_vm_ptr) (
    vmi_instance_t);
    status_t (
    *create_shm_snapshot_ptr) (
    vmi_instance_t);
    status_t (
    *destroy_shm_snapshot_ptr) (
    vmi_instance_t);
    size_t (
    *get_dgpma_ptr) (
    vmi_instance_t ,
    addr_t,
    void **,
    size_t);
    size_t (
    *get_dgvma_ptr) (
    vmi_instance_t,
    addr_t,
    pid_t,
    void**,
    size_t);
    status_t (
    *events_listen_ptr)(
    vmi_instance_t,
    uint32_t);
    status_t (
    *set_reg_access_ptr)(
    vmi_instance_t,
    reg_event_t);
    status_t (
    *set_intr_access_ptr)(
    vmi_instance_t,
    interrupt_event_t,
    uint8_t enabled);
    status_t (
    *set_mem_access_ptr)(
    vmi_instance_t,
    mem_event_t,
    vmi_mem_access_t);
    status_t (
    *start_single_step_ptr)(
    vmi_instance_t,
    single_step_event_t);
    status_t (
    *stop_single_step_ptr)(
    vmi_instance_t,
    uint32_t);
    status_t (
    *shutdown_single_step_ptr)(
    vmi_instance_t);
};
typedef struct driver_instance *driver_instance_t;

static driver_instance_t instance = NULL;

static void
driver_xen_setup(
    vmi_instance_t vmi)
{
    vmi->driver = safe_malloc(sizeof(xen_instance_t));
    memset(vmi->driver, 0, sizeof(xen_instance_t));
    instance->init_ptr = &xen_init;
    instance->destroy_ptr = &xen_destroy;
    instance->get_id_from_name_ptr = &xen_get_domainid_from_name;
    instance->get_name_from_id_ptr = &xen_get_name_from_domainid;
    instance->get_id_ptr = &xen_get_domainid;
    instance->set_id_ptr = &xen_set_domainid;
    instance->check_id_ptr = &xen_check_domainid;
    instance->get_name_ptr = &xen_get_domainname;
    instance->set_name_ptr = &xen_set_domainname;
    instance->get_memsize_ptr = &xen_get_memsize;
    instance->get_vcpureg_ptr = &xen_get_vcpureg;
    instance->set_vcpureg_ptr = &xen_set_vcpureg;
    instance->get_address_width_ptr = &xen_get_address_width;
    instance->read_page_ptr = &xen_read_page;
    instance->write_ptr = &xen_write;
    instance->is_pv_ptr = &xen_is_pv;
    instance->pause_vm_ptr = &xen_pause_vm;
    instance->resume_vm_ptr = &xen_resume_vm;
#if ENABLE_SHM_SNAPSHOT == 1
    instance->create_shm_snapshot_ptr = &xen_create_shm_snapshot;
    instance->destroy_shm_snapshot_ptr = &xen_destroy_shm_snapshot;
    instance->get_dgpma_ptr = &xen_get_dgpma;
    instance->get_dgvma_ptr = NULL;
#else
    instance->create_shm_snapshot_ptr = NULL;
    instance->destroy_shm_snapshot_ptr = NULL;
    instance->get_dgpma_ptr = NULL;
    instance->get_dgvma_ptr = NULL;
#endif
#if ENABLE_XEN_EVENTS==1
    instance->events_listen_ptr = &xen_events_listen;
    instance->set_reg_access_ptr = &xen_set_reg_access;
    instance->set_intr_access_ptr = &xen_set_intr_access;
    instance->set_mem_access_ptr = &xen_set_mem_access;
    instance->start_single_step_ptr = &xen_start_single_step;
    instance->stop_single_step_ptr = &xen_stop_single_step;
    instance->shutdown_single_step_ptr = &xen_shutdown_single_step;
#else
    instance->events_listen_ptr = NULL;
    instance->set_reg_access_ptr = NULL;
    instance->set_mem_access_ptr = NULL;
    instance->start_single_step_ptr = NULL;
    instance->stop_single_step_ptr = NULL;
    instance->shutdown_single_step_ptr = NULL;
#endif
}

static void
driver_kvm_setup(
    vmi_instance_t vmi)
{
    vmi->driver = safe_malloc(sizeof(kvm_instance_t));
    memset(vmi->driver, 0, sizeof(kvm_instance_t));
    instance->init_ptr = &kvm_init;
    instance->destroy_ptr = &kvm_destroy;
    instance->get_id_from_name_ptr = &kvm_get_id_from_name;
    instance->get_name_from_id_ptr = &kvm_get_name_from_id;
    instance->get_id_ptr = &kvm_get_id;
    instance->set_id_ptr = &kvm_set_id;
    instance->check_id_ptr = &kvm_check_id;
    instance->get_name_ptr = &kvm_get_name;
    instance->set_name_ptr = &kvm_set_name;
    instance->get_memsize_ptr = &kvm_get_memsize;
    instance->get_vcpureg_ptr = &kvm_get_vcpureg;
    instance->set_vcpureg_ptr = NULL;
    instance->get_address_width_ptr = NULL;
    instance->read_page_ptr = &kvm_read_page;
    instance->write_ptr = &kvm_write;
    instance->is_pv_ptr = &kvm_is_pv;
    instance->pause_vm_ptr = &kvm_pause_vm;
    instance->resume_vm_ptr = &kvm_resume_vm;
#if ENABLE_SHM_SNAPSHOT == 1
    instance->create_shm_snapshot_ptr = &kvm_create_shm_snapshot;
    instance->destroy_shm_snapshot_ptr = &kvm_destroy_shm_snapshot;
    instance->get_dgpma_ptr = &kvm_get_dgpma;
    instance->get_dgvma_ptr = &kvm_get_dgvma;
#else
    instance->create_shm_snapshot_ptr = NULL;
    instance->destroy_shm_snapshot_ptr = NULL;
    instance->get_dgpma_ptr = NULL;
    instance->get_dgvma_ptr = NULL;
#endif
    instance->events_listen_ptr = NULL;
    instance->set_reg_access_ptr = NULL;
    instance->set_intr_access_ptr = NULL;
    instance->set_mem_access_ptr = NULL;
    instance->start_single_step_ptr = NULL;
    instance->stop_single_step_ptr = NULL;
    instance->shutdown_single_step_ptr = NULL;
}

static void
driver_file_setup(
    vmi_instance_t vmi)
{
    vmi->driver = safe_malloc(sizeof(file_instance_t));
    memset(vmi->driver, 0, sizeof(file_instance_t));
    instance->init_ptr = &file_init;
    instance->destroy_ptr = &file_destroy;
    instance->get_id_from_name_ptr = NULL;  //TODO add get_id_from_name_ptr
    instance->get_name_from_id_ptr = NULL;  //TODO add get_name_from_id_ptr
    instance->get_id_ptr = NULL;    //TODO add get_id_ptr
    instance->set_id_ptr = NULL;    //TODO add set_id_ptr
    instance->check_id_ptr = NULL;     //TODO add check_id_ptr
    instance->get_name_ptr = &file_get_name;
    instance->set_name_ptr = &file_set_name;
    instance->get_memsize_ptr = &file_get_memsize;
    instance->get_address_width_ptr = NULL;
    instance->get_vcpureg_ptr = &file_get_vcpureg;
    instance->set_vcpureg_ptr = NULL;
    instance->read_page_ptr = &file_read_page;
    instance->write_ptr = &file_write;
    instance->is_pv_ptr = &file_is_pv;
    instance->pause_vm_ptr = &file_pause_vm;
    instance->resume_vm_ptr = &file_resume_vm;
    instance->events_listen_ptr = NULL;
    instance->set_reg_access_ptr = NULL;
    instance->set_intr_access_ptr = NULL;
    instance->set_mem_access_ptr = NULL;
    instance->start_single_step_ptr = NULL;
    instance->stop_single_step_ptr = NULL;
    instance->shutdown_single_step_ptr = NULL;
}

static void
driver_null_setup(
    vmi_instance_t vmi)
{
    vmi->driver = NULL;
    instance->init_ptr = NULL;
    instance->destroy_ptr = NULL;
    instance->get_id_from_name_ptr = NULL;
    instance->get_name_from_id_ptr = NULL;
    instance->get_id_ptr = NULL;
    instance->set_id_ptr = NULL;
    instance->check_id_ptr = NULL;
    instance->get_name_ptr = NULL;
    instance->set_name_ptr = NULL;
    instance->get_memsize_ptr = NULL;
    instance->get_address_width_ptr = NULL;
    instance->get_vcpureg_ptr = NULL;
    instance->set_vcpureg_ptr = NULL;
    instance->read_page_ptr = NULL;
    instance->is_pv_ptr = NULL;
    instance->pause_vm_ptr = NULL;
    instance->resume_vm_ptr = NULL;
    instance->events_listen_ptr = NULL;
    instance->set_reg_access_ptr = NULL;
    instance->set_intr_access_ptr = NULL;
    instance->set_mem_access_ptr = NULL;
    instance->start_single_step_ptr = NULL;
    instance->stop_single_step_ptr = NULL;
    instance->shutdown_single_step_ptr = NULL;
}

static driver_instance_t
driver_get_instance(
    vmi_instance_t vmi)
{
    if (NULL == vmi->driver || NULL == instance) {
        /* allocate memory for the function pointers, if needed */
        if (NULL == instance) {
            instance =
                (driver_instance_t)
                safe_malloc(sizeof(struct driver_instance));
        }

        /* assign the function pointers */
        if (VMI_XEN == vmi->mode) {
            driver_xen_setup(vmi);
        }
        else if (VMI_KVM == vmi->mode) {
            driver_kvm_setup(vmi);
        }
        else if (VMI_FILE == vmi->mode) {
            driver_file_setup(vmi);
        }
        else {
            driver_null_setup(vmi);
        }

    }
    return instance;
}

status_t
driver_init_mode(
    vmi_instance_t vmi,
    unsigned long id,
    char *name)
{
    unsigned long count = 0;

    /* see what systems are accessable */
    if (VMI_SUCCESS == xen_test(id, name)) {
        dbprint(VMI_DEBUG_DRIVER, "--found Xen\n");
        vmi->mode = VMI_XEN;
        count++;
    }
    if (VMI_SUCCESS == kvm_test(id, name)) {
        dbprint(VMI_DEBUG_DRIVER, "--found KVM\n");
        vmi->mode = VMI_KVM;
        count++;
    }
    if (VMI_SUCCESS == file_test(id, name)) {
        dbprint(VMI_DEBUG_DRIVER, "--found file\n");
        vmi->mode = VMI_FILE;
        count++;
    }

    /* if we didn't see exactly one system, report error */
    if (count == 0) {
        errprint("Could not find a live guest VM or file to use.\n");
        errprint("Opening a live guest VM requires root access.\n");
        return VMI_FAILURE;
    }
    else if (count > 1) {
        errprint
            ("Found more than one VMM or file to use,\nplease specify what you want instead of using VMI_AUTO.\n");
        return VMI_FAILURE;
    }
    else {  // count == 1
        return VMI_SUCCESS;
    }
}

status_t
driver_init(
    vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->init_ptr) {
        return ptrs->init_ptr(vmi);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_init function not implemented.\n");
        return VMI_FAILURE;
    }
}

void
driver_destroy(
    vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->destroy_ptr) {
        ptrs->destroy_ptr(vmi);
        free(vmi->driver);
        return;
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_destroy function not implemented.\n");
        return;
    }
}

unsigned long
driver_get_id_from_name(
    vmi_instance_t vmi,
    char *name)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->get_id_from_name_ptr) {
        return ptrs->get_id_from_name_ptr(vmi, name);
    }
    else {
        dbprint
            (VMI_DEBUG_DRIVER, "WARNING: driver_get_id_from_name function not implemented.\n");
        return 0;
    }
}

status_t
driver_get_name_from_id(
    vmi_instance_t vmi,
    unsigned long domid,
    char **name)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->get_name_from_id_ptr) {
        return ptrs->get_name_from_id_ptr(vmi, domid, name);
    }
    else {
        dbprint
            (VMI_DEBUG_DRIVER, "WARNING: driver_get_name_from_id function not implemented.\n");
        return 0;
    }
}

unsigned long
driver_get_id(
    vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->get_id_ptr) {
        return ptrs->get_id_ptr(vmi);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_id function not implemented.\n");
        return 0;
    }
}

void
driver_set_id(
    vmi_instance_t vmi,
    unsigned long id)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->set_id_ptr) {
        return ptrs->set_id_ptr(vmi, id);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_id function not implemented.\n");
        return;
    }
}

void
driver_check_id(
    vmi_instance_t vmi,
    unsigned long id)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->check_id_ptr) {
        ptrs->check_id_ptr(vmi, id);
        return;
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_check_id function not implemented.\n");
        return;
    }
}

status_t
driver_get_name(
    vmi_instance_t vmi,
    char **name)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->get_name_ptr) {
        return ptrs->get_name_ptr(vmi, name);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_name function not implemented.\n");
        return VMI_FAILURE;
    }
}

void
driver_set_name(
    vmi_instance_t vmi,
    char *name)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->set_name_ptr) {
        return ptrs->set_name_ptr(vmi, name);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_name function not implemented.\n");
        return;
    }
}

status_t
driver_get_memsize(
    vmi_instance_t vmi,
    uint64_t *size)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->get_memsize_ptr) {
        return ptrs->get_memsize_ptr(vmi, size);
    }
    else {
        dbprint
            (VMI_DEBUG_DRIVER, "WARNING: driver_get_memsize function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t
driver_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->get_vcpureg_ptr) {
        return ptrs->get_vcpureg_ptr(vmi, value, reg, vcpu);
    }
    else {
        dbprint
            (VMI_DEBUG_DRIVER, "WARNING: driver_get_vcpureg function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t
driver_set_vcpureg(
    vmi_instance_t vmi,
    reg_t value,
    registers_t reg,
    unsigned long vcpu)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->set_vcpureg_ptr){
        return ptrs->set_vcpureg_ptr(vmi, value, reg, vcpu);
    }
    else{
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_vcpureg function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t
driver_get_address_width(
    vmi_instance_t vmi,
    uint8_t * width)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->get_address_width_ptr) {
        return ptrs->get_address_width_ptr(vmi, width);
    }
    else {
        dbprint
            (VMI_DEBUG_DRIVER, "WARNING: driver_get_address_width function not implemented.\n");
        return VMI_FAILURE;
    }
}

void *
driver_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->read_page_ptr) {
        return ptrs->read_page_ptr(vmi, page);
    }
    else {
        dbprint
            (VMI_DEBUG_DRIVER, "WARNING: driver_read_page function not implemented.\n");
        return NULL;
    }
}

status_t
driver_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->write_ptr) {
        return ptrs->write_ptr(vmi, paddr, buf, length);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_write function not implemented.\n");
        return VMI_FAILURE;
    }
}

int
driver_is_pv(
    vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->is_pv_ptr) {
        return ptrs->is_pv_ptr(vmi);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_is_pv function not implemented.\n");
        return 0;
    }
}

status_t
driver_pause_vm(
    vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->pause_vm_ptr) {
        return ptrs->pause_vm_ptr(vmi);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_pause_vm function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t
driver_resume_vm(
    vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->resume_vm_ptr) {
        return ptrs->resume_vm_ptr(vmi);
    }
    else {
        dbprint
            (VMI_DEBUG_DRIVER, "WARNING: driver_resume_vm function not implemented.\n");
        return VMI_FAILURE;
    }
}

#if ENABLE_SHM_SNAPSHOT == 1
status_t driver_shm_snapshot_vm(
    vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->create_shm_snapshot_ptr) {
        return ptrs->create_shm_snapshot_ptr(vmi);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_shm_snapshot_vm function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t driver_destroy_shm_snapshot_vm(
    vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->destroy_shm_snapshot_ptr) {
        return ptrs->destroy_shm_snapshot_ptr(vmi);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_destroy_shm_snapshot_vm function not implemented.\n");
        return VMI_FAILURE;
    }
}

size_t driver_get_dgpma(
    vmi_instance_t vmi,
    addr_t paddr,
    void **medial_addr_ptr,
    size_t count)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->get_dgpma_ptr) {
        return ptrs->get_dgpma_ptr(vmi, paddr, medial_addr_ptr, count);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: get_dgpma_ptr function not implemented.\n");
        return 0;
    }
    return 0;
}

size_t
driver_get_dgvma(
    vmi_instance_t vmi,
    addr_t vaddr,
    pid_t pid,
    void** medial_addr_ptr,
    size_t count)
{
    driver_instance_t ptrs = driver_get_instance(vmi);

    if (NULL != ptrs && NULL != ptrs->get_dgvma_ptr) {
        return ptrs->get_dgvma_ptr(vmi, vaddr, pid, medial_addr_ptr, count);
    }
    else {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: get_dgvma_ptr function not implemented.\n");
        return 0;
    }
    return 0;
}
#endif

status_t driver_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->events_listen_ptr){
        return ptrs->events_listen_ptr(vmi, timeout);
    }
    else{
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_events_listen function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t driver_set_reg_access(
    vmi_instance_t vmi,
    reg_event_t event)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->set_reg_access_ptr){
        return ptrs->set_reg_access_ptr(vmi, event);
    }
    else{
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_reg_w_access function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t driver_set_intr_access(
    vmi_instance_t vmi,
    interrupt_event_t event,
    uint8_t enabled)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->set_intr_access_ptr){
        return ptrs->set_intr_access_ptr(vmi, event, enabled);
    }
    else{
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_intr_access function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t driver_set_mem_access(
    vmi_instance_t vmi,
    mem_event_t event,
    vmi_mem_access_t page_access_flag)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->set_mem_access_ptr){
        return ptrs->set_mem_access_ptr(vmi, event, page_access_flag);
    }
    else{
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_mem_access function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t driver_start_single_step(
    vmi_instance_t vmi,
    single_step_event_t event)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->start_single_step_ptr){
        return ptrs->start_single_step_ptr(vmi, event);
    }
    else{
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_start_single_step function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t driver_stop_single_step(
    vmi_instance_t vmi,
    unsigned long vcpu)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->stop_single_step_ptr){
        return ptrs->stop_single_step_ptr(vmi, vcpu);
    }
    else{
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_stop_single_step function not implemented.\n");
        return VMI_FAILURE;
    }
}

status_t driver_shutdown_single_step(
    vmi_instance_t vmi)
{
    driver_instance_t ptrs = driver_get_instance(vmi);
    if (NULL != ptrs && NULL != ptrs->shutdown_single_step_ptr){
        return ptrs->shutdown_single_step_ptr(vmi);
    }
    else{
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_shutdown_single_step function not implemented.\n");
        return VMI_FAILURE;
    }
}

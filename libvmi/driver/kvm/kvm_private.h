
/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
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

#ifndef KVM_PRIVATE_H
#define KVM_PRIVATE_H

// config.h is parsed in private.h (ENABLE_KVM_LEGACY)
#include "private.h"

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#ifndef ENABLE_KVM_LEGACY
# include <libkvmi.h>
# include "libkvmi_wrapper.h"
#endif

#include "libvirt_wrapper.h"

typedef struct kvm_instance {
    virConnectPtr conn;
    virDomainPtr dom;
    uint32_t id;
    char *name;
    char *ds_path;
    libvirt_wrapper_t libvirt;
#ifdef ENABLE_KVM_LEGACY
    int socket_fd;
#else
    void *kvmi;
    void *kvmi_dom;
    libkvmi_wrapper_t libkvmi;
    pthread_mutex_t kvm_connect_mutex;
    pthread_cond_t kvm_start_cond;
    unsigned int expected_pause_count;
    // store KVMI_EVENT_PAUSE_VCPU events poped by vmi_events_listen(vmi, 0)
    // to be used by vmi_resume_vm()
    struct kvmi_dom_event** pause_events_list;
    // dispatcher to handle VM events in each process_xxx functions
    status_t (*process_event[KVMI_NUM_EVENTS])(vmi_instance_t vmi, struct kvmi_dom_event *event);
    bool monitor_cr0_on;
    bool monitor_cr3_on;
    bool monitor_cr4_on;
    bool monitor_msr_all_on;
    bool monitor_intr_on;
    bool monitor_desc_on;
    // array of [VCPU] -> [boolean]
    // whether singlstep is enabled on a given VCPU
    bool *sstep_enabled;
#endif
} kvm_instance_t;

static inline kvm_instance_t *
kvm_get_instance(
    vmi_instance_t vmi)
{
    return ((kvm_instance_t *) vmi->driver.driver_data);
}

// kvm_put_memory is used by kvm_common.c
// and has different implementations
status_t
kvm_put_memory(vmi_instance_t vmi,
               addr_t paddr,
               uint32_t length,
               void *buf);

// shared by kvm.c and kvm_events.c
# ifndef ENABLE_KVM_LEGACY
void
kvmi_regs_to_libvmi(
    struct kvm_regs *kvmi_regs,
    struct kvm_sregs *kvmi_sregs,
    x86_registers_t *libvmi_regs);
# endif

#endif

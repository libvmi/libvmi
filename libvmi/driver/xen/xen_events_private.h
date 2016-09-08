/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * This file is part of LibVMI.
 *
 * Author: Nasser Salim (njsalim@sandia.gov)
 * Author: Steven Maresca (steve@zentific.com)
 * Author: Tamas K Lengyel (tamas@tklengyel.com)
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

/*
 * Portions of this header and dependent code is based upon that in xen-access,
 *    from the official Xen source distribution.  That code carries the
 *    following copyright notices and license.
 *
 * Copyright (c) 2011 Virtuata, Inc.
 * Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp), based on
 *   xenpaging.c
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#ifndef XEN_EVENTS_PRIVATE_H
#define XEN_EVENTS_PRIVATE_H

#include <sys/poll.h>
#include <unistd.h>
#include <xenctrl.h>
#include <libvmi/events.h>

#include "xen_events_abi.h"

typedef struct {
    xc_evtchn* xce_handle;
    int port;
    uint32_t evtchn_port;
    void *ring_page;
    union {
        mem_event_42_back_ring_t back_ring_42;
        mem_event_45_back_ring_t back_ring_45;
    };
    unsigned long long max_pages;
} xen_mem_event_t;

typedef struct {
    xc_evtchn* xce_handle;
    int port;
    uint32_t evtchn_port;
    void *ring_page;
    vm_event_46_back_ring_t back_ring_46;
    xen_pfn_t max_gpfn;
    uint32_t monitor_capabilities;
    bool monitor_singlestep_on;
    bool monitor_mem_access_on;
    bool monitor_intr_on;
    bool monitor_cr0_on;
    bool monitor_cr3_on;
    bool monitor_cr4_on;
    bool monitor_xcr0_on;
    bool monitor_msr_on;
} xen_vm_event_t;

/* Conversion matrix from LibVMI flags to Xen vm_event flags */
static const unsigned int event_response_conversion[] = {
    [VMI_EVENT_RESPONSE_EMULATE] = VM_EVENT_FLAG_EMULATE,
    [VMI_EVENT_RESPONSE_EMULATE_NOWRITE] = VM_EVENT_FLAG_EMULATE_NOWRITE,
    [VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP] = VM_EVENT_FLAG_TOGGLE_SINGLESTEP,
    [VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA] = VM_EVENT_FLAG_SET_EMUL_READ_DATA,
    [VMI_EVENT_RESPONSE_DENY] = VM_EVENT_FLAG_DENY,
    [VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID] = VM_EVENT_FLAG_ALTERNATE_P2M,
    [VMI_EVENT_RESPONSE_SET_REGISTERS] = VM_EVENT_FLAG_SET_REGISTERS,
};

typedef struct xen_events {
    union {
        xen_mem_event_t mem_event;
        xen_vm_event_t vm_event;
    };
} xen_events_t;

status_t xen_set_int3_access(vmi_instance_t vmi, bool enable);

/* Interface to Xen 4.1-4.5 events */
int xen_are_events_pending_41(vmi_instance_t vmi);
int xen_are_events_pending_42(vmi_instance_t vmi);
int xen_are_events_pending_45(vmi_instance_t vmi);
status_t xen_events_listen_41(vmi_instance_t vmi, uint32_t timeout);
status_t xen_events_listen_42(vmi_instance_t vmi, uint32_t timeout);
status_t xen_events_listen_45(vmi_instance_t vmi, uint32_t timeout);
status_t xen_set_reg_access_legacy(vmi_instance_t vmi, reg_event_t *event);
status_t xen_set_intr_access_legacy(vmi_instance_t vmi, interrupt_event_t *event, bool enabled);
status_t xen_set_mem_access_legacy(vmi_instance_t vmi,
                                   addr_t gpfn,
                                   vmi_mem_access_t page_access_flag,
                                   uint16_t vmm_pagetable_id);
status_t xen_start_single_step_legacy(vmi_instance_t vmi, single_step_event_t *event);
status_t xen_stop_single_step_legacy(vmi_instance_t vmi, uint32_t vcpu);
status_t xen_shutdown_single_step_legacy(vmi_instance_t vmi);

/* Interface to Xen 4.6+ events */
int xen_are_events_pending(vmi_instance_t vmi);
status_t xen_events_listen(vmi_instance_t vmi, uint32_t timeout);
status_t xen_set_reg_access(vmi_instance_t vmi, reg_event_t *event);
status_t xen_set_intr_access(vmi_instance_t vmi, interrupt_event_t *event, bool enabled);
status_t xen_set_mem_access(vmi_instance_t vmi,
                            addr_t gpfn,
                            vmi_mem_access_t page_access_flag,
                            uint16_t vmm_pagetable_id);
status_t xen_set_guest_requested_event(vmi_instance_t vmi, bool enabled);
status_t xen_set_debug_event(vmi_instance_t vmi, bool enabled);
status_t xen_set_cpuid_event(vmi_instance_t vmi, bool enabled);
status_t xen_start_single_step(vmi_instance_t vmi, single_step_event_t *event);
status_t xen_stop_single_step(vmi_instance_t vmi, uint32_t vcpu);
status_t xen_shutdown_single_step(vmi_instance_t vmi);


#endif

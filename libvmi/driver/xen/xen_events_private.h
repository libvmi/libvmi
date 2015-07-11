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

#if XEN_EVENTS_VERSION < 460
typedef int spinlock_t;
#include <xen/mem_event.h>
#else
#include <xen/vm_event.h>
#endif

#if XEN_EVENTS_VERSION < 450
#include <xen/hvm/save.h>
#else
#include <xen/memory.h>
#endif

#ifdef XENCTRL_HAS_XC_INTERFACE
typedef xc_evtchn* xc_evtchn_t;
#else
typedef int xc_evtchn_t;
#endif

typedef struct {
#if XEN_EVENTS_VERSION < 460
    xc_evtchn_t xce_handle;
    int port;
#if XEN_EVENTS_VERSION < 420
    mem_event_shared_page_t *shared_page;
#else
    uint32_t evtchn_port;
#endif
    void *ring_page;
    mem_event_back_ring_t back_ring;
    spinlock_t ring_lock;
    unsigned long long max_pages;
#endif // XEN_EVENTS < 460
} xen_mem_event_t;

typedef struct {
#if XEN_EVENTS_VERSION >= 460
    xc_evtchn_t xce_handle;
    int port;
    uint32_t evtchn_port;
    void *ring_page;
    vm_event_back_ring_t back_ring;
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
#endif
} xen_vm_event_t;

// Compatibility wrapper around mem_access versions
#if XEN_EVENTS_VERSION < 450
// Xen 4.0-4.4 type flags
typedef enum {
    COMPAT_MEMACCESS_INVALID = ~0,
    COMPAT_MEMACCESS_N = HVMMEM_access_n,
    COMPAT_MEMACCESS_R = HVMMEM_access_r,
    COMPAT_MEMACCESS_W = HVMMEM_access_w,
    COMPAT_MEMACCESS_RW = HVMMEM_access_rw,
    COMPAT_MEMACCESS_X = HVMMEM_access_x,
    COMPAT_MEMACCESS_RX = HVMMEM_access_rx,
    COMPAT_MEMACCESS_WX = HVMMEM_access_wx,
    COMPAT_MEMACCESS_RWX = HVMMEM_access_rwx,
    /*
     * Page starts off as r-x, but automatically
     * change to r-w on a write
     */
    COMPAT_MEMACCESS_RX2RW = HVMMEM_access_rx2rw,

#ifdef HVMMEM_access_n2rwx
    /*
     * Log access: starts off as n, automatically
     * goes to rwx, generating an event without
     * pausing the vcpu
     */
    COMPAT_MEMACCESS_N2RWX = HVMMEM_access_n2rwx
#else
    COMPAT_MEMACCESS_N2RWX = COMPAT_MEMACCESS_INVALID
#endif
} compat_COMPAT_MEMACCESS_t;
typedef hvmmem_access_t mem_access_t;

#else /* XEN_EVENTS_VERSION */
// Xen 4.5+ type flags
typedef enum {
    COMPAT_MEMACCESS_INVALID = ~0,
    COMPAT_MEMACCESS_N = XENMEM_access_n,
    COMPAT_MEMACCESS_R = XENMEM_access_r,
    COMPAT_MEMACCESS_W = XENMEM_access_w,
    COMPAT_MEMACCESS_RW = XENMEM_access_rw,
    COMPAT_MEMACCESS_X = XENMEM_access_x,
    COMPAT_MEMACCESS_RX = XENMEM_access_rx,
    COMPAT_MEMACCESS_WX = XENMEM_access_wx,
    COMPAT_MEMACCESS_RWX = XENMEM_access_rwx,
    /*
     * Page starts off as r-x, but automatically
     * change to r-w on a write
     */
    COMPAT_MEMACCESS_RX2RW = XENMEM_access_rx2rw,
    /*
     * Log access: starts off as n, automatically
     * goes to rwx, generating an event without
     * pausing the vcpu
     */
    COMPAT_MEMACCESS_N2RWX = XENMEM_access_n2rwx
} compat_mem_access_t;
typedef xenmem_access_t mem_access_t;

#endif /* XEN_EVENTS_VERSION */

/* Conversion matrix from LibVMI flags to Xen flags */
static const unsigned int compat_memaccess_conversion[] = {
    [VMI_MEMACCESS_INVALID] = COMPAT_MEMACCESS_INVALID,
    [VMI_MEMACCESS_N] = COMPAT_MEMACCESS_RWX,
    [VMI_MEMACCESS_R] = COMPAT_MEMACCESS_WX,
    [VMI_MEMACCESS_W] = COMPAT_MEMACCESS_RX,
    [VMI_MEMACCESS_X] = COMPAT_MEMACCESS_RW,
    [VMI_MEMACCESS_RW] = COMPAT_MEMACCESS_X,
    [VMI_MEMACCESS_RX] = COMPAT_MEMACCESS_W,
    [VMI_MEMACCESS_WX] = COMPAT_MEMACCESS_R,
    [VMI_MEMACCESS_RWX] = COMPAT_MEMACCESS_N,
    [VMI_MEMACCESS_W2X] = COMPAT_MEMACCESS_RX2RW,
    [VMI_MEMACCESS_RWX2N] = COMPAT_MEMACCESS_N2RWX
};

/* Conversion matrix from LibVMI flags to Xen vm_event flags */
static const unsigned int event_response_conversion[] = {
    [0 ... __VMI_EVENT_RESPONSE_MAX] = ~0, // Mark all flags invalid by default
#if XEN_EVENTS_VERSION >= 460
    [VMI_EVENT_RESPONSE_EMULATE] = VM_EVENT_FLAG_EMULATE,
    [VMI_EVENT_RESPONSE_EMULATE_NOWRITE] = VM_EVENT_FLAG_EMULATE_NOWRITE,
    [VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP] = VM_EVENT_FLAG_TOGGLE_SINGLESTEP,
#endif
};

typedef struct xen_events {
    union {
        xen_mem_event_t mem_event;
        xen_vm_event_t vm_event;
    };
} xen_events_t;

status_t xen_set_int3_access(vmi_instance_t vmi, bool enable);

#endif

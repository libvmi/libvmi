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
#ifndef XEN_EVENTS_H
#define XEN_EVENTS_H

#include <sys/poll.h>
#include <unistd.h>

#if ENABLE_XEN == 1 && ENABLE_XEN_EVENTS==1
#include <xenctrl.h>
#include <xen/mem_event.h>

#if XEN_EVENTS_VERSION < 450
#include <xen/hvm/save.h>
#else
#include <xen/memory.h>
#endif

typedef int spinlock_t;
#ifdef XENCTRL_HAS_XC_INTERFACE
typedef xc_evtchn* xc_evtchn_t;
#else
typedef int xc_evtchn_t;
#endif

typedef struct {
    xc_evtchn_t xce_handle;
    int port;
    mem_event_back_ring_t back_ring;
#if XEN_EVENTS_VERSION < 420
    mem_event_shared_page_t *shared_page;
#else
    uint32_t evtchn_port;
#endif
    void *ring_page;
    spinlock_t ring_lock;
    unsigned long long max_pages;
} xen_mem_event_t;

// Compatibility wrapper around mem_access versions
#if XEN_EVENTS_VERSION < 450
typedef enum {
    // Xen 4.0-4.4 type flags
    MEMACCESS_N = HVMMEM_access_n,
    MEMACCESS_R = HVMMEM_access_r,
    MEMACCESS_W = HVMMEM_access_w,
    MEMACCESS_RW = HVMMEM_access_rw,
    MEMACCESS_X = HVMMEM_access_x,
    MEMACCESS_RX = HVMMEM_access_rx,
    MEMACCESS_WX = HVMMEM_access_wx,
    MEMACCESS_RWX = HVMMEM_access_rwx,
    /*
     * Page starts off as r-x, but automatically
     * change to r-w on a write
     */
    MEMACCESS_RX2RW = HVMMEM_access_rx2rw,
    /*
     * Log access: starts off as n, automatically
     * goes to rwx, generating an event without
     * pausing the vcpu
     */
    MEMACCESS_N2RWX = HVMMEM_access_n2rwx
} compat_memaccess_t;

typedef hvmmem_access_t mem_access_t;

#else
// Xen 4.5+ type flags
typedef enum {
    MEMACCESS_N = XENMEM_access_n,
    MEMACCESS_R = XENMEM_access_r,
    MEMACCESS_W = XENMEM_access_w,
    MEMACCESS_RW = XENMEM_access_rw,
    MEMACCESS_X = XENMEM_access_x,
    MEMACCESS_RX = XENMEM_access_rx,
    MEMACCESS_WX = XENMEM_access_wx,
    MEMACCESS_RWX = XENMEM_access_rwx,
    /*
     * Page starts off as r-x, but automatically
     * change to r-w on a write
     */
    MEMACCESS_RX2RW = XENMEM_access_rx2rw,
    /*
     * Log access: starts off as n, automatically
     * goes to rwx, generating an event without
     * pausing the vcpu
     */
    MEMACCESS_N2RWX = XENMEM_access_n2rwx
} compat_memaccess_t;
typedef xenmem_access_t mem_access_t;

#endif

#else
typedef struct {
} xen_mem_event_t;

#endif /* ENABLE_XEN */
typedef struct xen_events {
    xen_mem_event_t mem_event;
} xen_events_t;

status_t xen_events_init(vmi_instance_t vmi);
void xen_events_destroy(vmi_instance_t vmi);
int xen_are_events_pending(vmi_instance_t vmi);
status_t xen_events_listen(vmi_instance_t vmi, uint32_t timeout);
status_t xen_set_reg_access(vmi_instance_t vmi, reg_event_t event);
status_t xen_set_intr_access(vmi_instance_t vmi, interrupt_event_t event, uint8_t enabled);
status_t xen_set_int3_access(vmi_instance_t vmi, interrupt_event_t event, uint8_t enabled);
status_t xen_set_mem_access(vmi_instance_t vmi, mem_event_t event, vmi_mem_access_t page_access_flag);
status_t xen_start_single_step(vmi_instance_t vmi, single_step_event_t event);
status_t xen_stop_single_step(vmi_instance_t vmi, uint32_t vcpu);
status_t xen_shutdown_single_step(vmi_instance_t vmi);

#endif

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
#include <xen/hvm/save.h>

typedef int spinlock_t;
#ifdef XENCTRL_HAS_XC_INTERFACE
#if XENCTRL_HAS_XC_INTERFACE==1
typedef xc_evtchn* xc_evtchn_t;
#else
#error Unknown libxenctrl interface version! This constitutes a bug and requires an update to the LibVMI Xen driver.
#endif
#else
typedef int xc_evtchn_t;
#endif

typedef struct {
    xc_evtchn_t xce_handle;
    int port;
    mem_event_back_ring_t back_ring;
#ifdef XENEVENT42
    uint32_t evtchn_port;
#elif XENEVENT41
    mem_event_shared_page_t *shared_page;
#else
#error "Unsupported Xen version for events"
#endif
    void *ring_page;
    spinlock_t ring_lock;
    unsigned long long max_pages;
} xen_mem_event_t;
#else
typedef struct {
} xen_mem_event_t;

#endif /* ENABLE_XEN */
typedef struct xen_events {
    xen_mem_event_t mem_event;
} xen_events_t;

status_t xen_events_init(vmi_instance_t vmi);
void xen_events_destroy(vmi_instance_t vmi);
status_t xen_events_listen(vmi_instance_t vmi, uint32_t timeout);
status_t xen_set_reg_access(vmi_instance_t vmi, reg_event_t event);
status_t xen_set_intr_access(vmi_instance_t vmi, interrupt_event_t event, uint8_t enabled);
status_t xen_set_int3_access(vmi_instance_t vmi, interrupt_event_t event, uint8_t enabled);
status_t xen_set_mem_access(vmi_instance_t vmi, mem_event_t event, vmi_mem_access_t page_access_flag);
status_t xen_start_single_step(vmi_instance_t vmi, single_step_event_t event);
status_t xen_stop_single_step(vmi_instance_t vmi, uint32_t vcpu);
status_t xen_shutdown_single_step(vmi_instance_t vmi);

#endif

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
/* Portions of this header and dependent code is based upon that in xen-access, 
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

#include "libvmi.h"
#include "private.h"
#include "driver/xen.h"
#include "driver/xen_private.h"
#include "driver/xen_events.h"

#include <string.h>

/*----------------------------------------------------------------------------
 * Helper functions
 */

/* Only build if Xen and Xen memory events are explicitly enabled by the 
 *  configure script.
 *
 * Use the xenctrl interface version defined (from xenctrl.h) to validate
 *  that all the features we expect are present. This avoids build failures
 *  on 4.0.x which had some memory event functions defined, yet lacked
 *  all of the features LibVMI needs.
 */
#if ENABLE_XEN==1 && ENABLE_XEN_EVENTS==1 && XENCTRL_HAS_XC_INTERFACE
static xen_events_t *xen_get_events(vmi_instance_t vmi) 
{
    return xen_get_instance(vmi)->events;
}

#define ADDR (*(volatile long *) addr)
static inline int test_and_set_bit(int nr, volatile void *addr)
{
    int oldbit;
    asm volatile (
        "btsl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit), "=m" (ADDR)
        : "Ir" (nr), "m" (ADDR) : "memory");
    return oldbit;
}

/* Spinlock and mem event definitions */
#define SPIN_LOCK_UNLOCKED 0

static inline void spin_lock(spinlock_t *lock)
{
    while ( test_and_set_bit(1, lock) );
}

static inline void spin_lock_init(spinlock_t *lock)
{
    *lock = SPIN_LOCK_UNLOCKED;
}

static inline void spin_unlock(spinlock_t *lock)
{
    *lock = SPIN_LOCK_UNLOCKED;
}

#define xen_event_ring_lock_init(_m)  spin_lock_init(&(_m)->ring_lock)
#define xen_event_ring_lock(_m)       spin_lock(&(_m)->ring_lock)
#define xen_event_ring_unlock(_m)     spin_unlock(&(_m)->ring_lock)

int wait_for_event_or_timeout(xc_interface *xch, xc_evtchn *xce, unsigned long ms)
{
    struct pollfd fd = { .fd = xc_evtchn_fd(xce), .events = POLLIN | POLLERR };
    int port;
    int rc;

    rc = poll(&fd, 1, ms);
    if ( rc == -1 )
    {
        if (errno == EINTR)
            return 0;

        errprint("Poll exited with an error\n");
        goto err;
    }

    if ( rc == 1 )
    {
        port = xc_evtchn_pending(xce);
        if ( port == -1 )
        {
            errprint("Failed to read port from event channel\n");
            goto err;
        }

        rc = xc_evtchn_unmask(xce, port);
        if ( rc != 0 )
        {
            errprint("Failed to unmask event channel port\n");
            goto err;
        }
    }
    else
        port = -1;

    return port;

 err:
    return -errno;
}

int get_mem_event(xen_mem_event_t *mem_event, mem_event_request_t *req)
{
    mem_event_back_ring_t *back_ring;
    RING_IDX req_cons;

    xen_event_ring_lock(mem_event);

    back_ring = &mem_event->back_ring;
    req_cons = back_ring->req_cons;

    // Copy request
    memcpy(req, RING_GET_REQUEST(back_ring, req_cons), sizeof(*req));
    req_cons++;

    // Update ring
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;

    xen_event_ring_unlock(mem_event);

    return 0;
}

static int put_mem_response(xen_mem_event_t *mem_event, mem_event_response_t *rsp)
{
    mem_event_back_ring_t *back_ring;
    RING_IDX rsp_prod;

    xen_event_ring_lock(mem_event);

    back_ring = &mem_event->back_ring;
    rsp_prod = back_ring->rsp_prod_pvt;

    // Copy response
    memcpy(RING_GET_RESPONSE(back_ring, rsp_prod), rsp, sizeof(*rsp));
    rsp_prod++;

    // Update ring
    back_ring->rsp_prod_pvt = rsp_prod;
    RING_PUSH_RESPONSES(back_ring);

    xen_event_ring_unlock(mem_event);

    return 0;
}

static int resume_domain(vmi_instance_t vmi, mem_event_response_t *rsp)
{
    xc_interface * xch;
    xen_events_t * xe;
    unsigned long dom;
    int ret;

    // Get xen handle and domain.
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);
    xe = xen_get_events(vmi);

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return -1;
    }
    if ( !xe ) {
        errprint("%s error: invalid xen_event_t handle\n", __FUNCTION__);
        return -1;
    }
    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return -1;
    }

    // Put the page info on the ring
    ret = put_mem_response(&xe->mem_event, rsp);
    if ( ret != 0 )
        return ret;

    // Tell Xen page is ready
    ret = xc_mem_access_resume(xch, dom, rsp->gfn);
    ret = xc_evtchn_notify(xe->mem_event.xce_handle, xe->mem_event.port);
    return ret;
}

status_t process_register(vmi_instance_t vmi,
                          registers_t reg,
                          mem_event_request_t req)
{

    vmi_event_t * event = g_hash_table_lookup(vmi->reg_events, &reg);

    if(event) {
            /* reg_event.equal allows you to set a reg event for
             *  a specific VALUE of the register (passed in req.gfn)
             */
            if(event->reg_event.equal && event->reg_event.equal != req.gfn)
                return VMI_SUCCESS;

            event->reg_event.value = req.gfn;
            event->vcpu_id = req.vcpu_id;

#ifdef HVM_PARAM_MEMORY_EVENT_MSR
            /* Special case: indicate which MSR is being written */
            if(event->reg_event.reg == MSR_ALL)
                event->reg_event.context = req.gla;
#endif
            
            /* TODO MARESCA: note that vmi_event_t lacks a flags member
             *   so we have no req.flags equivalent. might need to add
             *   e.g !!(req.flags & MEM_EVENT_FLAG_VCPU_PAUSED)  would be nice
             */
            event->callback(vmi, event);

            return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

status_t process_mem(vmi_instance_t vmi, mem_event_request_t req)
{

    struct hvm_hw_cpu ctx;
    xc_interface * xch;
    unsigned long dom;
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    /* TODO, cleanup: ctx is unused here */
    xc_domain_hvm_getcontext_partial(xch, dom,
            HVM_SAVE_CODE(CPU), req.vcpu_id, &ctx, sizeof(ctx));

    memevent_page_t * page = g_hash_table_lookup(vmi->mem_events, &req.gfn);
    vmi_mem_access_t out_access;
    if(req.access_r) out_access = VMI_MEMACCESS_R;
    else if(req.access_w) out_access = VMI_MEMACCESS_W;
    else if(req.access_x) out_access = VMI_MEMACCESS_X;

    if (page)
    {

        vmi_event_t *event = NULL;

        if (page->event && (page->event->mem_event.in_access & out_access))
        {
            event = page->event;

            event->mem_event.gla = req.gla;
            event->mem_event.gfn = req.gfn;
            event->mem_event.offset = req.offset;
            event->mem_event.out_access = out_access;
            event->vcpu_id = req.vcpu_id;

            event->callback(vmi, event);
        }

        if (page->byte_events)
        {
            event_iter_t i;
            addr_t *pa;
            for_each_event(vmi, i, page->byte_events, &pa, &event)
            {
                if ((event->mem_event.in_access & out_access)
                        && *pa == req.gfn + req.offset)
                {
                    event->mem_event.gla = req.gla;
                    event->mem_event.gfn = req.gfn;
                    event->mem_event.offset = req.offset;
                    event->mem_event.out_access = out_access;
                    event->vcpu_id = req.vcpu_id;

                    event->callback(vmi, event);
                }
            }
        }

        /* TODO MARESCA: decide whether it's worthwhile to emulate xen-access here and call the following
         *    note: the 'access' variable is basically discarded in that spot. perhaps it's really only called
         *    to validate that the event is accessible (maybe that it's not consumed elsewhere??)
         * hvmmem_access_t access;
         * rc = xc_hvm_get_mem_access(xch, domain_id, event.mem_event.gfn, &access);
         */

        return VMI_SUCCESS;
    }
    return VMI_FAILURE;
}

status_t process_single_step_event(vmi_instance_t vmi, mem_event_request_t req)
{
    xc_interface * xch;
    unsigned long dom;
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    vmi_event_t * event = g_hash_table_lookup(vmi->ss_events, &req.vcpu_id);

    if (event)
    {
        event->ss_event.gla = req.gla;
        event->ss_event.gfn = req.gfn;
        event->vcpu_id = req.vcpu_id;

        event->callback(vmi, event);
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

//----------------------------------------------------------------------------
// Driver functions

void xen_events_destroy(vmi_instance_t vmi)
{
    int rc;
    xc_interface * xch;
    xen_events_t * xe;
    unsigned long dom;

    // Get xen handle and domain.
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);
    xe = xen_get_events(vmi);

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return;
    }
    if ( !xe ) {
        errprint("%s error: invalid xen_events_t handle\n", __FUNCTION__);
        return;
    }
    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return;
    }
    
    //A precaution to not leave vcpus stuck in single step
    xen_shutdown_single_step(vmi);

    /* Unregister for all events */
    rc = xc_hvm_set_mem_access(xch, dom, HVMMEM_access_rwx, ~0ull, 0);
    rc = xc_hvm_set_mem_access(xch, dom, HVMMEM_access_rwx, 0, xe->mem_event.max_pages);
    rc = xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_INT3, HVMPME_mode_disabled);
    rc = xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_CR0, HVMPME_mode_disabled);
    rc = xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_CR3, HVMPME_mode_disabled);
    rc = xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_CR4, HVMPME_mode_disabled);
#ifdef HVM_PARAM_MEMORY_EVENT_MSR
    rc = xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_MSR, HVMPME_mode_disabled);
#endif
    rc = xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_SINGLE_STEP, HVMPME_mode_disabled);

    xen_events_listen(vmi, 0);

    // Turn off mem events
#ifdef XENEVENT42
    munmap(xe->mem_event.ring_page, getpagesize());
    rc = xc_mem_access_disable(xch, dom);
#elif XENEVENT41

    if (xe->mem_event.ring_page != NULL) {
        munlock(xe->mem_event.ring_page, getpagesize());
        free(xe->mem_event.ring_page);
    }

    if (xe->mem_event.shared_page != NULL) {
        munlock(xe->mem_event.shared_page, getpagesize());
        free(xe->mem_event.shared_page);
    }

    rc = xc_mem_event_disable(xch, dom);
#endif

    if ( rc != 0 )
    {
        errprint("Error disabling mem events.\n");
    }

    /* TODO MARESCA - might want the evtchn_bind flag like in xen-access here
     * for when this function is called before it was bound
     */
    // Unbind VIRQ
    rc = xc_evtchn_unbind(xe->mem_event.xce_handle, xe->mem_event.port);
    if ( rc != 0 )
    {
        errprint("Error unbinding event port\n");
    }
    //xe->mem_event.port = -1;

    // Close event channel
    rc = xc_evtchn_close(xe->mem_event.xce_handle);
    if ( rc != 0 )
    {
        errprint("Error closing event channel\n");
    }
    //xe->mem_event.xce_handle = NULL;

    free(xe);
}

status_t xen_events_init(vmi_instance_t vmi)
{
    xen_events_t * xe;
    xc_interface * xch;
    xc_domaininfo_t * dom_info;
    unsigned long dom;
    unsigned long ring_pfn, mmap_pfn;
    int rc;

    /* Xen (as of 4.3) only supports events for HVM domains 
     *  This is likely to expand to PV in the future, but
     *  until such time, enforce this restriction
     */
    if(!xen_get_instance(vmi)->hvm){
        errprint("Xen events: only HVM domains are supported.\n");
        return VMI_FAILURE;
    }

    // Get xen handle and domain.
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return;
    }
    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return;
    }

    // Allocate memory
    xe = calloc(1, sizeof(xen_events_t));
    if ( !xe ) {
        errprint("%s error: allocation for xen_events_t failed\n", __FUNCTION__);
        return;
    }
    
    dbprint("Init xen events with xch == %llx\n", (unsigned long long)xch);

    // Initialise lock
    xen_event_ring_lock_init(&xe->mem_event);

#ifdef XENEVENT42
    // Initialise shared page
    xc_get_hvm_param(xch, dom, HVM_PARAM_ACCESS_RING_PFN, &ring_pfn);
    mmap_pfn = ring_pfn;
    xe->mem_event.ring_page =
        xc_map_foreign_batch(xch, dom, PROT_READ | PROT_WRITE, &mmap_pfn, 1);
    if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB )
    {
        /* Map failed, populate ring page */
        rc = xc_domain_populate_physmap_exact(xch,
                                              dom,
                                              1, 0, 0, &ring_pfn);
        if ( rc != 0 )
        {
            errprint("Failed to populate ring gfn\n");
            goto err;
        }

        mmap_pfn = ring_pfn;
        xe->mem_event.ring_page =
            xc_map_foreign_batch(xch, dom,
                                    PROT_READ | PROT_WRITE, &mmap_pfn, 1);
        if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB )
        {
            errprint("Could not map the ring page\n");
            goto err;
        }
    }

#elif XENEVENT41

    rc = posix_memalign(&xe->mem_event.ring_page, getpagesize(), getpagesize());
    if (rc != 0 ) {
        errprint("Could not allocate the ring page!\n");
        goto err;
    }

    rc = mlock(xe->mem_event.ring_page, getpagesize());
    if (rc != 0 ) {
        errprint("Could not lock the ring page!\n");
        free(xe->mem_event.ring_page);
        xe->mem_event.ring_page = NULL;
        goto err;
    }

    rc = posix_memalign(&xe->mem_event.shared_page, getpagesize(), getpagesize());
    if (rc != 0 ) {
        errprint("Could not allocate the shared page!\n");
        goto err;
    }

    rc = mlock(xe->mem_event.shared_page, getpagesize());
    if (rc != 0 ) {
        errprint("Could not lock the shared page!\n");
        free(xe->mem_event.shared_page);
        xe->mem_event.shared_page = NULL;
        goto err;
    }

#endif

#ifdef XENEVENT42
    // Initialise Xen
    rc = xc_mem_access_enable(xch, dom, &(xe->mem_event.evtchn_port));
#elif XENEVENT41
    rc = xc_mem_event_enable(xch, dom, xe->mem_event.shared_page,
                                 xe->mem_event.ring_page);

#endif

    if ( rc != 0 )
    {
        switch ( errno ) {
            case EBUSY:
                errprint("events are (or were) active on this domain\n");
                break;
            case ENODEV:
                errprint("EPT not supported for this guest\n");
                break;
            default:
                errprint("Error initialising memory events: %s\n", strerror(errno));
                break;
        }
        goto err;
    }

    // Open event channel
    xe->mem_event.xce_handle = xc_evtchn_open(NULL, 0);
    if ( xe->mem_event.xce_handle == NULL )
    {
        errprint("Failed to open event channel\n");
        goto err;
    }

    // Bind event notification
#ifdef XENEVENT42
    rc = xc_evtchn_bind_interdomain(
          xe->mem_event.xce_handle, dom, xe->mem_event.evtchn_port);
#elif XENEVENT41
    rc = xc_evtchn_bind_interdomain(
          xe->mem_event.xce_handle, dom, xe->mem_event.shared_page->port);
#endif

    if ( rc < 0 )
    {
        errprint("Failed to bind event channel\n");
        goto err;
    }

    xe->mem_event.port = rc;
    dbprint("Bound to event channel on port == %d\n", xe->mem_event.port);

    // Initialise ring
    SHARED_RING_INIT((mem_event_sring_t *)xe->mem_event.ring_page);
    BACK_RING_INIT(&xe->mem_event.back_ring,
                   (mem_event_sring_t *)xe->mem_event.ring_page,
                   getpagesize());

    /* Now that the ring is set, remove it from the guest's physmap */
    if ( xc_domain_decrease_reservation_exact(xch,
                    dom, 1, 0, &ring_pfn) )
        errprint("Failed to remove ring from guest physmap\n");

    // Get domaininfo
    /* TODO MARESCA non allocated would work fine here via &dominfo below */
    dom_info = malloc(sizeof(xc_domaininfo_t));
    if ( dom_info == NULL )
    {
        errprint("Error allocating memory for domain info\n");
        goto err;
    }

    rc = xc_domain_getinfolist(xch, dom, 1, dom_info);
    if ( rc != 1 )
    {
        errprint("Error getting domain info\n");
        goto err;
    }

    // This is mostly nice for setting global access.
    // There may be a better way to manage this.
    xe->mem_event.max_pages = dom_info->max_pages;
    free(dom_info);

    xen_get_instance(vmi)->events = xe;
    return VMI_SUCCESS;

 err:
    errprint("Failed initialize xen events.\n");
    xen_events_destroy(vmi);
    return VMI_FAILURE;
}

status_t xen_set_reg_access(vmi_instance_t vmi, reg_event_t event)
{
    xc_interface * xch = xen_get_xchandle(vmi);
    unsigned long dom = xen_get_domainid(vmi);
    int value = HVMPME_mode_disabled;
    int hvm_param;

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    } 

    switch(event.in_access){
        case VMI_REGACCESS_N: break;
        case VMI_REGACCESS_W:
            value = HVMPME_mode_sync;
            if(event.async)
                value = HVMPME_mode_async;

            /* NOTE: this is completely ignored within Xen for MSR events */
            if(event.onchange)
                value |= HVMPME_onchangeonly;

            break;
        case VMI_REGACCESS_R:
        case VMI_REGACCESS_RW:
            errprint("Register read events are unavailable in Xen.\n");
            return VMI_FAILURE;
            break;
        default:
            errprint("Unknown register access mode: %d\n", event.in_access);
            return VMI_FAILURE;
    }

    switch(event.reg){
        case CR0:
            hvm_param = HVM_PARAM_MEMORY_EVENT_CR0;
            break;
        case CR3:
            hvm_param = HVM_PARAM_MEMORY_EVENT_CR3;
            break;
        case CR4:
            hvm_param = HVM_PARAM_MEMORY_EVENT_CR4;
            break;
#ifdef HVM_PARAM_MEMORY_EVENT_MSR
        case MSR_ALL:
            hvm_param = HVM_PARAM_MEMORY_EVENT_MSR;
#endif
            break;
        default:
            errprint("Tried to register for unsupported register event.\n");
            return VMI_FAILURE;
    }
    if(xc_set_hvm_param(xch, dom, hvm_param, value))
        return VMI_FAILURE;
    return VMI_SUCCESS;
}

status_t xen_set_mem_access(vmi_instance_t vmi, mem_event_t event, vmi_mem_access_t page_access_flag)
{
    int rc;
    hvmmem_access_t access;
    xc_interface * xch = xen_get_xchandle(vmi);
    xen_events_t * xe = xen_get_events(vmi);
    unsigned long dom = xen_get_domainid(vmi);

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( !xe ) {
        errprint("%s error: invalid xen_events_t handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }
 
    addr_t page_key = event.physical_address >> 12;

    uint64_t npages = page_key + event.npages > xe->mem_event.max_pages
        ? xe->mem_event.max_pages - page_key: event.npages;

    // Convert betwen vmi_mem_access_t and hvmmem_access_t
    // Xen does them backwards....
    switch(page_access_flag){
        case VMI_MEMACCESS_INVALID: return VMI_FAILURE;
        case VMI_MEMACCESS_N: access = HVMMEM_access_rwx; break;
        case VMI_MEMACCESS_R: access = HVMMEM_access_wx; break;
        case VMI_MEMACCESS_W: access = HVMMEM_access_rx; break;
        case VMI_MEMACCESS_X: access = HVMMEM_access_rw; break;
        case VMI_MEMACCESS_RW: access = HVMMEM_access_x; break;
        case VMI_MEMACCESS_RX: access = HVMMEM_access_w; break;
        case VMI_MEMACCESS_WX: access = HVMMEM_access_r; break;
        case VMI_MEMACCESS_RWX: access = HVMMEM_access_n; break;
        case VMI_MEMACCESS_X_ON_WRITE: access = HVMMEM_access_rx2rw; break;
    }

    dbprint("--Setting memaccess for domain %lu on page: %"PRIu64" npages: %"PRIu64"\n",
        dom, event.page, npages);
    if((rc = xc_hvm_set_mem_access(xch, dom, access, page_key, npages))){
        errprint("xc_hvm_set_mem_access failed with code: %d\n", rc);
        return VMI_FAILURE;
    }
    dbprint("--Done Setting memaccess on page: %"PRIu64"\n", event.page);
    return VMI_SUCCESS;
}

status_t xen_set_int3_access(vmi_instance_t vmi, int enabled)
{
    int param = HVMPME_mode_disabled;
    if(enabled)
        param = HVMPME_mode_sync;

    return xc_set_hvm_param(
        xen_get_xchandle(vmi), xen_get_domainid(vmi),
        HVM_PARAM_MEMORY_EVENT_INT3, param);
}

status_t xen_start_single_step(vmi_instance_t vmi, single_step_event_t event)
{
    unsigned long dom = xen_get_domainid(vmi);
    int rc = -1;
    uint32_t i = 0;

    dbprint("--Starting single step on domain %lu\n", dom);
    
    rc = xc_set_hvm_param(
            xen_get_xchandle(vmi), dom,
            HVM_PARAM_MEMORY_EVENT_SINGLE_STEP, HVMPME_mode_sync);

    if (rc<0) {
        errprint("Error %d setting HVM single step\n", rc);
        return VMI_FAILURE;
    }
    
    for(;i < MAX_SINGLESTEP_VCPUS; i++){
        if(CHECK_VCPU_SINGLESTEP(event, i)) {
            dbprint("--Setting MTF flag on vcpu %u\n", i);
            if(xen_set_domain_debug_control(vmi, i, 1) == VMI_FAILURE) {
                errprint("Error setting MTF flag on vcpu %u\n", i);
                goto rewind;
            }
        }
    }

    return VMI_SUCCESS;

 rewind:
    do {
        xen_stop_single_step(vmi, i);
    }while(i--);
    
    return VMI_FAILURE;
}

status_t xen_stop_single_step(vmi_instance_t vmi, uint32_t vcpu)
{
    unsigned long dom = xen_get_domainid(vmi);
    status_t ret = VMI_FAILURE;

    dbprint("--Removing MTF flag from vcpu %u\n", vcpu);
    
    ret = xen_set_domain_debug_control(vmi, vcpu, 0);

    return ret;
}

status_t xen_shutdown_single_step(vmi_instance_t vmi) {
    unsigned long dom = xen_get_domainid(vmi);
    int rc = -1;
    uint32_t i=0;

    dbprint("--Shutting down single step on domain %lu\n", dom);
    
    for(;i<vmi->num_vcpus; i++) {
        xen_stop_single_step(vmi, i);
    }

    rc = xc_set_hvm_param(
            xen_get_xchandle(vmi), dom,
            HVM_PARAM_MEMORY_EVENT_SINGLE_STEP, HVMPME_mode_disabled);

    if (rc<0) {
        errprint("Error %d disabling HVM single step\n", rc);
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;    
}

status_t xen_events_listen(vmi_instance_t vmi, uint32_t timeout)
{
    xc_interface * xch;
    xen_events_t * xe;
    mem_event_request_t req;
    mem_event_response_t rsp;
    unsigned long dom;

    int rc = -1;
    status_t vrc = VMI_FAILURE;

    /* TODO determine whether we should force the required=1 for
     *   singlestep and int3, for which that is a necessity.
     * Alternatively, an error could be issued
     */
    int required = 0;

    // Get xen handle and domain.
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);
    xe = xen_get_events(vmi);

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( !xe ) {
        errprint("%s error: invalid xen_events_t handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    // Set whether the access listener is required
    rc = xc_domain_set_access_required(xch, dom, required);
    if ( rc < 0 ) {
        errprint("Error %d setting mem_access listener required\n", rc);
    }

    if(!vmi->shutting_down && timeout > 0) {
        dbprint("--Waiting for xen events...(%"PRIu32" ms)\n", timeout);
        rc = wait_for_event_or_timeout(xch, xe->mem_event.xce_handle, timeout);
        if ( rc < -1 ) {
            errprint("Error while waiting for event.\n");
            return VMI_FAILURE;
        }
    }

    while ( RING_HAS_UNCONSUMED_REQUESTS(&xe->mem_event.back_ring) ) {
        rc = get_mem_event(&xe->mem_event, &req);
        if ( rc != 0 ) {
            errprint("Error getting event.\n");
            return VMI_FAILURE;
        }

        memset( &rsp, 0, sizeof (rsp) );
        rsp.vcpu_id = req.vcpu_id;
        rsp.flags = req.flags;

        switch(req.reason){
            case MEM_EVENT_REASON_VIOLATION:
                dbprint("--Caught mem event!\n");
                rsp.gfn = req.gfn;
                rsp.p2mt = req.p2mt;

                if(!vmi->shutting_down) {
                    vrc = process_mem(vmi, req);
                }

                /*MARESCA do we need logic here to reset flags on a page? see xen-access.c
                 *    specifically regarding write/exec/int3 inspection and the code surrounding
                 *    the variables default_access and after_first_access
                 */

                break;
            case MEM_EVENT_REASON_CR0:
                if(!vmi->shutting_down) {
                    vrc = process_register(vmi, CR0, req);
                }
                break;
            case MEM_EVENT_REASON_CR3:
                if(!vmi->shutting_down) {
                    dbprint("--Caught CR3 event!\n");
                    vrc = process_register(vmi, CR3, req);
                }
                break;
#ifdef HVM_PARAM_MEMORY_EVENT_MSR
            case MEM_EVENT_REASON_MSR:
                if(!vmi->shutting_down) {
                    dbprint("--Caught MSR event!\n");
                    vrc = process_register(vmi, MSR_ALL, req);
                }
                break;
#endif
            case MEM_EVENT_REASON_CR4:
                if(!vmi->shutting_down) {
                    vrc = process_register(vmi, CR4, req);
                }
                break;
            case MEM_EVENT_REASON_SINGLESTEP:
                if(!vmi->shutting_down) {
                    dbprint("--Caught single step event!\n");
                    vrc = process_single_step_event(vmi, req);
                }
                break;
            case MEM_EVENT_REASON_INT3:
                /* TODO MARESCA need to handle this;
                 * see xen-unstable.hg/tools/include/xen/mem_event.h
                 */
            default:
                errprint("UNKNOWN REASON CODE %d\n", req.reason);
                vrc = VMI_FAILURE;
                break;
        }

        rc = resume_domain(vmi, &rsp);
        if ( rc != 0 ) {
            errprint("Error resuming domain.\n");
            return VMI_FAILURE;
        }
    }

    dbprint("--Finished handling event.\n");
    return vrc;
}
#else
status_t xen_events_listen(vmi_instance_t vmi, uint32_t timeout){
    return VMI_FAILURE;
}

status_t xen_set_reg_access(vmi_instance_t vmi, reg_event_t event){
    return VMI_FAILURE;
}

status_t xen_set_mem_access(vmi_instance_t vmi, mem_event_t event, vmi_mem_access_t page_access_flag){
return VMI_FAILURE;
}
status_t xen_start_single_step(vmi_instance_t vmi, single_step_event_t event){
    return VMI_FAILURE;
}
status_t xen_stop_single_step(vmi_instance_t vmi, uint32_t vcpu){
    return VMI_FAILURE;
}
status_t xen_shutdown_single_step(vmi_instance_t vmi){
    return VMI_FAILURE;
}
status_t xen_events_init(vmi_instance_t vmi){
    return VMI_FAILURE;
}
void xen_events_destroy(vmi_instance_t vmi){
}
#endif /* ENABLE_XEN */

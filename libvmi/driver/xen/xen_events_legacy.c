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
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
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

#include <string.h>

#include "private.h"
#include "driver/xen/xen.h"
#include "driver/xen/xen_private.h"
#include "driver/xen/xen_events.h"
#include "driver/xen/xen_events_private.h"

/*----------------------------------------------------------------------------
 * Helper functions
 */
static inline xen_events_t *xen_get_events(vmi_instance_t vmi)
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

static int resume_domain(vmi_instance_t vmi)
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

    // Tell Xen we have finished processing the requests
#if XEN_EVENTS_VERSION < 450
    // The last argument is actually ignored by Xen.
    ret = xc_mem_access_resume(xch, dom, 0);
#else
    // The last (unused) argument is now removed.
    ret = xc_mem_access_resume(xch, dom);
#endif
    ret = xc_evtchn_notify(xe->mem_event.xce_handle, xe->mem_event.port);
    return ret;
}

status_t process_interrupt_event(vmi_instance_t vmi,
                          interrupts_t intr,
                          mem_event_request_t req)
{

    int rc                      = -1;
    status_t status             = VMI_FAILURE;
    vmi_event_t * event         = g_hash_table_lookup(vmi->interrupt_events, &intr);
    xc_interface * xch          = xen_get_xchandle(vmi);
    unsigned long domain_id     = xen_get_domainid(vmi);

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( domain_id == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if(event) {
        event->interrupt_event.gfn = req.gfn;
        event->interrupt_event.offset = req.offset;
        event->interrupt_event.gla = req.gla;
        event->interrupt_event.intr = intr;
        event->interrupt_event.reinject = -1;
        event->vcpu_id = req.vcpu_id;

        /* Will need to refactor if another interrupt is accessible
         *  via events, and needs differing setup before callback.
         *  ..but this basic structure should be adequate for now.
         */

        event->callback(vmi, event);

        if(-1 == event->interrupt_event.reinject) {
            errprint("%s Need to specify reinjection behaviour!\n", __FUNCTION__);
            return VMI_FAILURE;
        }

        switch(intr){
        case INT3:
            /* Reinject (callback may decide) */
            if(1 == event->interrupt_event.reinject) {
                dbprint(VMI_DEBUG_XEN, "rip %"PRIx64" gfn %"PRIx64"\n",
                    event->interrupt_event.gla, event->interrupt_event.gfn);

                /* Undocumented enough to be worth describing at length:
                 *  If enabled, INT3 events are reported via the mem events
                 *  facilities of Xen only for the 1-byte 0xCC variant of the
                 *  instruction. The 2-byte 0xCD imm8 variant taking the
                 *  interrupt vector as an operand (i.e., 0xCD03) is NOT
                 *  reported in the same fashion (These details are valid as of
                 *  Xen 4.3).
                 *
                 *  In order for INT3 to be handled correctly by the VM
                 *  kernel and subsequently passed on to the debugger within a
                 *  VM, the trap must be re-injected. Because only 0xCC is in
                 *  play for events, the instruction length involved is only
                 *  one byte.
                 */
                #define TRAP_int3              3
                rc = xc_hvm_inject_trap(xch, domain_id, req.vcpu_id,
                        TRAP_int3,         /* Vector 3 for INT3 */
                        HVMOP_TRAP_sw_exc, /* Trap type, here a software intr */
                        ~0u, /* error code. ~0u means 'ignore' */
                         event->interrupt_event.insn_length,
                         0   /* cr2 need not be preserved */
                    );

                /* NOTE: Inability to re-inject constitutes a serious error.
                 *  (E.g., some program like a debugger in the guest is
                 *  awaiting SIGTRAP in order to trigger to re-write/emulation
                 *  of the instruction(s) it replaced..without which the
                 *  debugger's target program may be suspended with little hope
                 *  of resuming.)
                 *
                 * Further, the trap handler in kernel land may
                 *  itself be placed into an unrecoverable state if extreme
                 *  caution is not used here.
                 *
                 * However, the hypercall (and subsequently the libxc function)
                 *  return non-zero for Xen 4.1 and 4.2 even for successful
                 *  actions...so, ignore rc if version < 4.3.
                 *
                 * For future reference, this is a failed reinjection, as
                 * shown via 'xl dmesg' (the domain is forced to crash intentionally by Xen):
                 *  (XEN) <vm_resume_fail> error code 7
                 *  (XEN) domain_crash_sync called from vmcs.c:1107
                 *  (XEN) Domain 449 (vcpu#1) crashed on cpu#0:
                 *
                */
#if __XEN_INTERFACE_VERSION__ >= 0x00040300
                if (rc < 0) {
                    errprint("%s : Xen event error %d re-injecting int3 (benign result for 4.1 >= Xen < 4.3)\n", __FUNCTION__, rc);
                    status = VMI_FAILURE;
                    break;
                }
#else
#warning Xen version installed has interrupt reinjection with unusable return value.
/* NOTE: 4.2.3 has the required patch
 *   i.e., 'fix HVMOP_inject_trap return value on success'
 * But this cannot be inferred via __XEN_INTERFACE_VERSION__, which is only
 *  updated for major versions.
 */
#endif
            }

            status = VMI_SUCCESS;

            break;
        default:
            errprint("%s : Xen event - unknown interrupt %d\n", __FUNCTION__, intr);
            status = VMI_FAILURE;
            break;
        }
    }

    return status;
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

#if __XEN_INTERFACE_VERSION__ >= 0x00040400
            if(event->reg_event.reg != MSR_ALL)
                event->reg_event.previous = req.gla;
#endif
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


/*
 * This function clears up the page access flags and queues each event
 * registered on that page for re-registration using vmi_step_event.
 */
status_t process_unhandled_mem(vmi_instance_t vmi, memevent_page_t *page,
        mem_event_request_t *req)
{

    // Clear the page's access flags
    mem_access_event_t event = { 0 };
    event.physical_address = page->key << 12;
    event.npages = 1;
    xen_set_mem_access(vmi, &event, VMI_MEMACCESS_N, 0);

    // Queue the VMI_MEMEVENT_PAGE
    if (page->event) {
        vmi_step_event(vmi, page->event, req->vcpu_id, 1, NULL);
    }

    // Queue each VMI_MEMEVENT_BYTE
    if (page->byte_events)
    {
        GHashTableIter i;
        addr_t *pa;
        vmi_event_t *loop;
        ghashtable_foreach(page->byte_events, i, &pa, &loop)
        {
            vmi_step_event(vmi, loop, req->vcpu_id, 1, NULL);
        }

        // Free up memory of byte events GHashTable
        g_hash_table_destroy(page->byte_events);
    }

    // Clear page from LibVMI GhashTable
    g_hash_table_remove(vmi->mem_events, &page->key);

    return VMI_SUCCESS;
}

void issue_mem_cb(vmi_instance_t vmi, vmi_event_t *event,
        mem_event_request_t *req, vmi_mem_access_t out_access) {
    event->mem_event.gla = req->gla;
    event->mem_event.gfn = req->gfn;
    event->mem_event.offset = req->offset;
    event->mem_event.out_access = out_access;
    event->vcpu_id = req->vcpu_id;
    event->callback(vmi, event);
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
    vmi_mem_access_t out_access = VMI_MEMACCESS_INVALID;
    if(req.access_r) out_access |= VMI_MEMACCESS_R;
    if(req.access_w) out_access |= VMI_MEMACCESS_W;
    if(req.access_x) out_access |= VMI_MEMACCESS_X;

    if (page)
    {
        uint8_t cb_issued = 0;
        // To prevent use-after-free of 'page' in case it is freed after the first cb
        GHashTable *byte_events = page->byte_events;

        if (page->event && (page->event->mem_event.in_access & out_access))
        {
            issue_mem_cb(vmi, page->event, &req, out_access);
            cb_issued = 1;
        }

        if (byte_events)
        {
            // Check if the offset has a byte-event registered
            addr_t pa = (req.gfn<<12) + req.offset;
            vmi_event_t *byte_event = (vmi_event_t *)g_hash_table_lookup(byte_events, &pa);

            if(byte_event && (byte_event->mem_event.in_access & out_access))
            {
                issue_mem_cb(vmi, byte_event, &req, out_access);
                cb_issued = 1;
            }
        }

        /*
         * When using VMI_MEMEVENT_BYTE the page-fault may be triggered
         * at an offset that doesn't trigger a callback to the user. If these
         * events are not catched and cleared the VM will halt. On the other hand
         * if these events are cleared the user won't get the callback when the
         * target offset is hit, therefore the events need to be re-registered
         * after the fault has been cleared.
         */
        if(!cb_issued)
        {
            if(VMI_FAILURE == process_unhandled_mem(vmi, page, &req))
            {
                goto errdone;
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

    /*
     * TODO: Could this happen when using multi-vCPU VMs where multiple vCPU's trigger
     *       the same violation and the event is already being passed to vmi_step_event?
     *       The event in that case would be already removed from the GHashTable so
     *       the second violation on the other vCPU would not get delivered..
     */

    errprint("Caught a memory event that had no handler registered in LibVMI @ GFN %"PRIu32" (0x%"PRIx64"), access: %u\n",
        req.gfn, (req.gfn<<12) + req.offset, out_access);

errdone:
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

    errprint("%s error: no singlestep handler is registered in LibVMI\n", __FUNCTION__);
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

    vmi_pause_vm(vmi);

    //A precaution to not leave vcpus stuck in single step
    xen_shutdown_single_step(vmi);

    /* Unregister for all events */
#if XEN_EVENTS_VERSION < 450
    rc = xc_hvm_set_mem_access(xch, dom, (mem_access_t)COMPAT_MEMACCESS_RWX, ~0ull, 0);
    rc = xc_hvm_set_mem_access(xch, dom, (mem_access_t)COMPAT_MEMACCESS_RWX, 0, xe->mem_event.max_pages);
#else
    rc = xc_set_mem_access(xch, dom, (mem_access_t)COMPAT_MEMACCESS_RWX, ~0ull, 0);
    rc = xc_set_mem_access(xch, dom, (mem_access_t)COMPAT_MEMACCESS_RWX, 0, xe->mem_event.max_pages);
#endif
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
#if XEN_EVENTS_VERSION == 410
    if (xe->mem_event.ring_page != NULL) {
        munlock(xe->mem_event.ring_page, getpagesize());
        free(xe->mem_event.ring_page);
    }

    if (xe->mem_event.shared_page != NULL) {
        munlock(xe->mem_event.shared_page, getpagesize());
        free(xe->mem_event.shared_page);
    }

    rc = xc_mem_event_disable(xch, dom);
#else
    munmap(xe->mem_event.ring_page, getpagesize());
    rc = xc_mem_access_disable(xch, dom);
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
    xen_get_instance(vmi)->events = NULL;

    vmi_resume_vm(vmi);
}

status_t xen_events_init(vmi_instance_t vmi)
{
    xen_events_t * xe = NULL;
    xc_interface * xch = NULL;
    xc_domaininfo_t dom_info = {0};
    unsigned long dom = 0;
    unsigned long ring_pfn = 0;
    unsigned long mmap_pfn = 0;
    int rc = 0;

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
        return VMI_FAILURE;
    }
    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    // Allocate memory
    xe = calloc(1, sizeof(xen_events_t));
    if ( !xe ) {
        errprint("%s error: allocation for xen_events_t failed\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    xen_get_instance(vmi)->events = xe;

    dbprint(VMI_DEBUG_XEN, "Init xen events with xch == %llx\n", (unsigned long long)xch);

    rc = xc_domain_getinfolist(xch, dom, 1, &dom_info);
    if ( rc != 1 )
    {
        errprint("Error getting domain info\n");
        goto err;
    }

    if(!(dom_info.flags & XEN_DOMINF_paused) && VMI_FAILURE == vmi_pause_vm(vmi))
    {
        errprint("Failed to pause VM\n");
        goto err;
    }

    // This is mostly nice for setting global access.
    // There may be a better way to manage this.
    xe->mem_event.max_pages = dom_info.max_pages;

    // Initialise lock
    xen_event_ring_lock_init(&xe->mem_event);

    /* Initialize the shared pages and enable mem events */
    int tries = 0;

#if XEN_EVENTS_VERSION == 410
    rc = posix_memalign((void**)&xe->mem_event.ring_page, getpagesize(),
            getpagesize());
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

    rc = posix_memalign((void**)&xe->mem_event.shared_page, getpagesize(),
            getpagesize());
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

enable:
    rc = xc_mem_event_enable(xch, dom, xe->mem_event.shared_page,
                                 xe->mem_event.ring_page);
    goto enable_done;

reinit:
    xc_mem_event_disable(xch, dom);
    goto enable;

#elif XEN_EVENTS_VERSION < 450
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
enable:
    rc = xc_mem_access_enable(xch, dom, &(xe->mem_event.evtchn_port));
    goto enable_done;

reinit:
    xc_mem_access_disable(xch, dom);
    goto enable;

#else // 4.5 style
enable:
    /* Enable mem access and map the ring page */
    xe->mem_event.ring_page =
            xc_mem_access_enable(xch, dom, &(xe->mem_event.evtchn_port));

    rc = xe->mem_event.ring_page ? 0 : 1;
    goto enable_done;

reinit:
    xc_mem_access_disable(xch, dom);
    goto enable;
#endif

enable_done:
    if ( rc != 0 )
    {
        switch ( errno ) {
            case EBUSY:
                errprint("events are (or were) active on this domain\n");
                if(!tries) {
                    errprint("trying to disable and re-enable events\n");
                    tries++;
                    goto reinit;
                }
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

    /* This causes errors when going from VMI_PARTIAL->VMI_COMPLETE on Xen 4.1.2 */
    /* No longer required on Xen 4.5 */
#if XEN_EVENTS_VERSION == 420
    /* Now that the ring is set, remove it from the guest's physmap */
    if ( xc_domain_decrease_reservation_exact(xch,
                    dom, 1, 0, &ring_pfn) )
    {
        errprint("Failed to remove ring from guest physmap\n");
        goto err;
    }
#endif

    // Open event channel
    xe->mem_event.xce_handle = xc_evtchn_open(NULL, 0);
    if ( xe->mem_event.xce_handle == NULL )
    {
        errprint("Failed to open event channel\n");
        goto err;
    }

    // Bind event notification
#if XEN_EVENTS_VERSION == 410
    rc = xc_evtchn_bind_interdomain(
          xe->mem_event.xce_handle, dom, xe->mem_event.shared_page->port);
#else
    rc = xc_evtchn_bind_interdomain(
          xe->mem_event.xce_handle, dom, xe->mem_event.evtchn_port);
#endif

    if ( rc < 0 )
    {
        errprint("Failed to bind event channel\n");
        goto err;
    }

    xe->mem_event.port = rc;
    dbprint(VMI_DEBUG_XEN, "Bound to event channel on port == %d\n", xe->mem_event.port);

    // Initialise ring
    SHARED_RING_INIT((mem_event_sring_t *)xe->mem_event.ring_page);
    BACK_RING_INIT(&xe->mem_event.back_ring,
                   (mem_event_sring_t *)xe->mem_event.ring_page,
                   getpagesize());

    if(!(dom_info.flags & XEN_DOMINF_paused))
    {
        vmi_resume_vm(vmi);
    }
    return VMI_SUCCESS;

 err:
    errprint("Failed initialize xen events.\n");
    xen_events_destroy(vmi);

    if(!(dom_info.flags & XEN_DOMINF_paused))
    {
        vmi_resume_vm(vmi);
    }
    return VMI_FAILURE;
}

status_t xen_set_reg_access(vmi_instance_t vmi, reg_event_t *event)
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

    switch(event->in_access){
        case VMI_REGACCESS_N: break;
        case VMI_REGACCESS_W:
            value = HVMPME_mode_sync;
            if(event->async)
                value = HVMPME_mode_async;

            /* NOTE: this is completely ignored within Xen for MSR events */
            if(event->onchange)
                value |= HVMPME_onchangeonly;

            break;
        case VMI_REGACCESS_R:
        case VMI_REGACCESS_RW:
            errprint("Register read events are unavailable in Xen.\n");
            return VMI_FAILURE;
            break;
        default:
            errprint("Unknown register access mode: %d\n", event->in_access);
            return VMI_FAILURE;
    }

    switch(event->reg){
        case CR0:
#if XEN_EVENTS_VERSION == 420
            /* More info as to why:
             * http://xenbits.xen.org/gitweb/?p=xen.git;a=commit;h=5d570c1d0274cac3b333ef378af3325b3b69905e */
            errprint("The majority of events on CR0 are unavailable for Xen 4.2 - 4.4.\n");
#endif
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
    if (xc_set_hvm_param(xch, dom, hvm_param, value))
        return VMI_FAILURE;
    return VMI_SUCCESS;
}

status_t xen_set_mem_access(vmi_instance_t vmi, mem_access_event_t *event,
                            vmi_mem_access_t page_access_flag, uint16_t vmm_pagetable_id)
{
    int rc;
    mem_access_t access;
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
    if ( page_access_flag >= __VMI_MEMACCESS_MAX || page_access_flag <= VMI_MEMACCESS_INVALID ) {
        errprint("%s error: invalid memaccess setting requested\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    /*
     * Setting a page write-only or write-execute in EPT triggers and EPT misconfiguration error
     * which is unhandled by Xen (at least up to 4.3) and instantly crashes the domain on the first trigger.
     *
     * See Intel® 64 and IA-32 Architectures Software Developer’s Manual
     * 8.2.3.1 EPT Misconfigurations
     * AN EPT misconfiguration occurs if any of the following is identified while translating a guest-physical address:
     * * The value of bits 2:0 of an EPT paging-structure entry is either 010b (write-only) or 110b (write/execute).
     */
    if(page_access_flag == VMI_MEMACCESS_R || page_access_flag == VMI_MEMACCESS_RX) {
        errprint("%s error: can't set requested memory access, unsupported by EPT.\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    addr_t page_key = event->physical_address >> 12;

    uint64_t npages = page_key + event->npages > xe->mem_event.max_pages
        ? xe->mem_event.max_pages - page_key: event->npages;

    // Convert betwen vmi_mem_access_t and mem_access_t
    // Xen does them backwards....
    access = compat_memaccess_conversion[page_access_flag];

    dbprint(VMI_DEBUG_XEN, "--Setting memaccess for domain %lu on physical address: %"PRIu64" npages: %"PRIu64"\n",
        dom, event->physical_address, npages);

#if XEN_EVENTS_VERSION < 450
    rc = xc_hvm_set_mem_access(xch, dom, access, page_key, npages);
#else
    rc = xc_set_mem_access(xch, dom, access, page_key, npages);
#endif

    if(rc) {
        errprint("xc_hvm_set_mem_access failed with code: %d\n", rc);
        return VMI_FAILURE;
    }
    dbprint(VMI_DEBUG_XEN, "--Done Setting memaccess on physical address: %"PRIu64"\n", event->physical_address);
    return VMI_SUCCESS;
}

status_t xen_set_intr_access(vmi_instance_t vmi, interrupt_event_t *event, bool enabled)
{

    switch(event->intr){
    case INT3:
        return xen_set_int3_access(vmi, enabled);
        break;
    default:
        errprint("Xen driver does not support enabling events for interrupt: %"PRIu32"\n", event->intr);
        break;
    }

    return VMI_FAILURE;
}

status_t xen_set_int3_access(vmi_instance_t vmi, bool enabled)
{
    xc_interface * xch = xen_get_xchandle(vmi);
    unsigned long dom = xen_get_domainid(vmi);
    int param = HVMPME_mode_disabled;

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( enabled ) {
        param = HVMPME_mode_sync;
    }

    return xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_INT3, param);
}

status_t xen_start_single_step(vmi_instance_t vmi, single_step_event_t *event)
{
    unsigned long dom = xen_get_domainid(vmi);
    int rc = -1;
    uint32_t i = 0;

    dbprint(VMI_DEBUG_XEN, "--Starting single step on domain %lu\n", dom);

    rc = xc_set_hvm_param(
            xen_get_xchandle(vmi), dom,
            HVM_PARAM_MEMORY_EVENT_SINGLE_STEP, HVMPME_mode_sync);

    if (rc<0) {
        errprint("Error %d setting HVM single step\n", rc);
        return VMI_FAILURE;
    }

    for(;i < MAX_SINGLESTEP_VCPUS; i++){
        if(CHECK_VCPU_SINGLESTEP(*event, i)) {
            dbprint(VMI_DEBUG_XEN, "--Setting MTF flag on vcpu %u\n", i);
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

    dbprint(VMI_DEBUG_XEN, "--Removing MTF flag from vcpu %u\n", vcpu);

    ret = xen_set_domain_debug_control(vmi, vcpu, 0);

    return ret;
}

status_t xen_shutdown_single_step(vmi_instance_t vmi) {
    unsigned long dom = xen_get_domainid(vmi);
    int rc = -1;
    uint32_t i=0;

    dbprint(VMI_DEBUG_XEN, "--Shutting down single step on domain %lu\n", dom);

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

int xen_are_events_pending(vmi_instance_t vmi)
{
    xen_events_t *xe = xen_get_events(vmi);

    if ( !xe ) {
        errprint("%s error: invalid xen_events_t handle\n", __FUNCTION__);
        return -1;
    }

    return RING_HAS_UNCONSUMED_REQUESTS(&xe->mem_event.back_ring);

}

status_t xen_events_listen(vmi_instance_t vmi, uint32_t timeout)
{
    xc_interface * xch;
    xen_events_t * xe;
    mem_event_request_t req;
    mem_event_response_t rsp;
    unsigned long dom;

    int rc = -1;
    status_t vrc = VMI_SUCCESS;

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
    rc = xc_domain_set_access_required(xch, dom, vmi->event_listener_required);
    if ( rc < 0 ) {
#if XEN_EVENTS_VERSION == 410
        // FIXME41: Xen 4.1.2 apparently mostly returns -1 for any call to this,
        // so just suppress the error for now
        dbprint(VMI_DEBUG_XEN, "Error %d setting mem_access listener required to %d\n",
            rc, vmi->event_listener_required);
#else
        errprint("Error %d setting mem_access listener required to %d\n",
            rc, vmi->event_listener_required);
#endif
    }

    if(!vmi->shutting_down && timeout > 0) {
        dbprint(VMI_DEBUG_XEN, "--Waiting for xen events...(%"PRIu32" ms)\n", timeout);
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
                dbprint(VMI_DEBUG_XEN, "--Caught mem event!\n");
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
                dbprint(VMI_DEBUG_XEN, "--Caught CR0 event!\n");
                if(!vmi->shutting_down) {
                    vrc = process_register(vmi, CR0, req);
                }
                break;
            case MEM_EVENT_REASON_CR3:
                dbprint(VMI_DEBUG_XEN, "--Caught CR3 event!\n");
                if(!vmi->shutting_down) {
                    vrc = process_register(vmi, CR3, req);
                }
                break;
#ifdef HVM_PARAM_MEMORY_EVENT_MSR
            case MEM_EVENT_REASON_MSR:
                if(!vmi->shutting_down) {
                    dbprint(VMI_DEBUG_XEN, "--Caught MSR event!\n");
                    vrc = process_register(vmi, MSR_ALL, req);
                }
                break;
#endif
            case MEM_EVENT_REASON_CR4:
                dbprint(VMI_DEBUG_XEN, "--Caught CR4 event!\n");
                if(!vmi->shutting_down) {
                    vrc = process_register(vmi, CR4, req);
                }
                break;
            case MEM_EVENT_REASON_SINGLESTEP:
                dbprint(VMI_DEBUG_XEN, "--Caught single step event!\n");
                if(!vmi->shutting_down) {
                    vrc = process_single_step_event(vmi, req);
                }
                break;
            case MEM_EVENT_REASON_INT3:
                if(!vmi->shutting_down) {
                    dbprint(VMI_DEBUG_XEN, "--Caught int3 interrupt event!\n");
                    vrc = process_interrupt_event(vmi, INT3, req);
                }
                break;
            default:
                errprint("UNKNOWN REASON CODE %d\n", req.reason);
                vrc = VMI_FAILURE;
                break;
        }

        // Put the response on the ring
        rc = put_mem_response(&xe->mem_event, &rsp);
        if ( rc != 0 ) {
            errprint("Error putting event response on the ring.\n");
            return VMI_FAILURE;
        }

        dbprint(VMI_DEBUG_XEN, "--Finished handling event.\n");
    }

    // We only resume the domain once all requests are processed from the ring
    rc = resume_domain(vmi);
    if ( rc != 0 ) {
        errprint("Error resuming domain.\n");
        return VMI_FAILURE;
    }

    return vrc;
}

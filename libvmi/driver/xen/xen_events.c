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

static inline
xen_events_t *xen_get_events(vmi_instance_t vmi)
{
    return xen_get_instance(vmi)->events;
}

int wait_for_event_or_timeout(xc_interface *xch,
                              xc_evtchn *xce,
                              unsigned long ms)
{
    struct pollfd fd = {
            .fd = xc_evtchn_fd(xce),
            .events = POLLIN | POLLERR
        };
    int port;
    int rc = poll(&fd, 1, ms);

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

static inline
void get_request(xen_vm_event_t *mem_event,
                 vm_event_request_t *req)
{
    vm_event_back_ring_t *back_ring;
    RING_IDX req_cons;

    back_ring = &mem_event->back_ring;
    req_cons = back_ring->req_cons;

    // Copy request
    memcpy(req, RING_GET_REQUEST(back_ring, req_cons), sizeof(*req));
    req_cons++;

    // Update ring
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;
}

static inline
void put_response(xen_vm_event_t *mem_event,
                  vm_event_response_t *rsp)
{
    vm_event_back_ring_t *back_ring;
    RING_IDX rsp_prod;

    back_ring = &mem_event->back_ring;
    rsp_prod = back_ring->rsp_prod_pvt;

    // Copy response
    memcpy(RING_GET_RESPONSE(back_ring, rsp_prod), rsp, sizeof(*rsp));
    rsp_prod++;

    // Update ring
    back_ring->rsp_prod_pvt = rsp_prod;
    RING_PUSH_RESPONSES(back_ring);
}

static int resume_domain(vmi_instance_t vmi)
{
    xc_interface * xch = xen_get_xchandle(vmi);
    xen_events_t * xe = xen_get_events(vmi);
    domid_t dom = xen_get_domainid(vmi);

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

    return xc_evtchn_notify(xe->vm_event.xce_handle, xe->vm_event.port);
}

/*
 * Here we check for response flags placed on the event in the callback
 * that allows triggering Xen vm_event response flags.
 */
static inline
void process_response ( event_response_t response, vmi_event_t* event, vm_event_request_t *rsp )
{
    if ( response && event ) {
        uint32_t i = VMI_EVENT_RESPONSE_NONE+1;

        for (;i<__VMI_EVENT_RESPONSE_MAX;i++)
        {
            uint32_t bit_set = !!(response & (1u << i));

            if ( bit_set && event_response_conversion[i] != ~0 )
            {
                switch ( i )
                {
                case VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID:
                    rsp->altp2m_idx = event->vmm_pagetable_id;
                    break;
                case VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA:
                    if ( event->emul_data ) {
                        rsp->flags |= VMI_EVENT_RESPONSE_EMULATE;

                        if ( event->emul_data->size < sizeof(rsp->data.emul_read_data.data) )
                            rsp->data.emul_read_data.size = event->emul_data->size;
                        else
                            rsp->data.emul_read_data.size = sizeof(rsp->data.emul_read_data.data);

                        memcpy(&rsp->data.emul_read_data.data,
                               &event->emul_data->data,
                               rsp->data.emul_read_data.size);

                        if ( !event->emul_data->dont_free )
                            free(event->emul_data);
                    }
                    break;
                };

                rsp->flags |= event_response_conversion[i];
            }
        }
    }
}

status_t process_interrupt_event(vmi_instance_t vmi,
                                 interrupts_t intr,
                                 vm_event_request_t *req,
                                 vm_event_request_t *rsp)
{
    int rc              = -1;
    status_t status     = VMI_FAILURE;
    vmi_event_t * event = g_hash_table_lookup(vmi->interrupt_events, &intr);
    xc_interface * xch  = xen_get_xchandle(vmi);
    domid_t domain_id   = xen_get_domainid(vmi);

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( domain_id == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( event )
    {
        event->interrupt_event.gfn = req->u.software_breakpoint.gfn;
        event->interrupt_event.offset = req->data.regs.x86.rip & VMI_BIT_MASK(0,11);
        event->interrupt_event.gla = req->data.regs.x86.rip;
        event->interrupt_event.intr = intr;
        event->interrupt_event.reinject = -1;
        event->regs.x86 = (x86_registers_t *)&req->data.regs.x86;
        event->vcpu_id = req->vcpu_id;

        /* Will need to refactor if another interrupt is accessible
         *  via events, and needs differing setup before callback.
         *  ..but this basic structure should be adequate for now.
         */

        process_response( event->callback(vmi, event), event, rsp );

        if(-1 == event->interrupt_event.reinject) {
            errprint("%s Need to specify reinjection behaviour!\n", __FUNCTION__);
            return VMI_FAILURE;
        }

        switch(intr)
        {
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
                    rc = xc_hvm_inject_trap(xch, domain_id, req->vcpu_id,
                            TRAP_int3,         /* Vector 3 for INT3 */
                            HVMOP_TRAP_sw_exc, /* Trap type, here a software intr */
                            ~0u, /* error code. ~0u means 'ignore' */
                            1,   /* Instruction length. Xen INT3 events are
                                  *  exclusively specific to 0xCC with no operand,
                                  *  providing a guarantee that this is 1 byte only.
                                  */
                            0    /* cr2 need not be preserved */
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

                    if (rc < 0) {
                        errprint("%s : Xen event error %d re-injecting software breakpoint\n", __FUNCTION__, rc);
                        status = VMI_FAILURE;
                        break;
                    }
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

static inline
status_t process_register(vmi_instance_t vmi,
                          registers_t reg,
                          vm_event_request_t *req,
                          vm_event_request_t *rsp)
{
    vmi_event_t * event = g_hash_table_lookup(vmi->reg_events, &reg);

    if ( event )
    {
        switch ( reg )
        {
            case MSR_ALL:
                event->reg_event.context = req->u.mov_to_msr.msr;
                event->reg_event.value = req->u.mov_to_msr.value;
                break;
            case CR0:
            case CR3:
            case CR4:
            case XCR0:
                /*
                 * event->reg_event.equal allows for setting a reg event for
                 *  a specific VALUE of the register
                 */
                if ( event->reg_event.equal &&
                     event->reg_event.equal != req->u.write_ctrlreg.new_value )
                    return VMI_SUCCESS;

                event->reg_event.value = req->u.write_ctrlreg.new_value;
                event->reg_event.previous = req->u.write_ctrlreg.old_value;
                break;
        }

        event->vcpu_id = req->vcpu_id;
        vmi->event_callback = 1;
        process_response ( event->callback(vmi, event), event, rsp );
        vmi->event_callback = 0;

        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}


/*
 * This function clears up the page access flags and queues each event
 * registered on that page for re-registration using vmi_step_event.
 */
status_t process_unhandled_mem(vmi_instance_t vmi,
                               memevent_page_t *page,
                               vm_event_request_t *req)
{

    // Clear the page's access flags
    mem_access_event_t event = { 0 };
    event.physical_address = page->key << 12;
    event.npages = 1;
    xen_set_mem_access(vmi, &event, VMI_MEMACCESS_N,
                       (req->flags & VM_EVENT_FLAG_ALTERNATE_P2M) ? req->altp2m_idx : 0);

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

static inline
event_response_t issue_mem_cb(vmi_instance_t vmi,
                  vmi_event_t *event,
                  vm_event_request_t *req,
                  vmi_mem_access_t out_access)
{
    event->mem_event.gla = req->u.mem_access.gla;
    event->mem_event.gfn = req->u.mem_access.gfn;
    event->mem_event.offset = req->u.mem_access.offset;
    event->mem_event.out_access = out_access;
    event->vcpu_id = req->vcpu_id;
    return event->callback(vmi, event);
}

status_t process_mem(vmi_instance_t vmi,
                     vm_event_request_t *req,
                     vm_event_response_t *rsp)
{

    xc_interface * xch = xen_get_xchandle(vmi);
    domid_t dom = xen_get_domainid(vmi);

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    rsp->u.mem_access = req->u.mem_access;

    memevent_page_t * page = g_hash_table_lookup(vmi->mem_events, &req->u.mem_access.gfn);
    vmi_mem_access_t out_access = VMI_MEMACCESS_INVALID;
    if(req->u.mem_access.flags & MEM_ACCESS_R) out_access |= VMI_MEMACCESS_R;
    if(req->u.mem_access.flags & MEM_ACCESS_W) out_access |= VMI_MEMACCESS_W;
    if(req->u.mem_access.flags & MEM_ACCESS_X) out_access |= VMI_MEMACCESS_X;

    if ( page )
    {
        uint8_t cb_issued = 0;
        // To prevent use-after-free of 'page' in case it is freed after the first cb
        GHashTable *byte_events = page->byte_events;

        if (page->event && (page->event->mem_event.in_access & out_access))
        {
            page->event->regs.x86 = (x86_registers_t *)&req->data.regs.x86;
            page->event->vmm_pagetable_id = req->altp2m_idx;
            vmi->event_callback = 1;
            process_response( issue_mem_cb(vmi, page->event, req, out_access), page->event, rsp );
            vmi->event_callback = 0;
            cb_issued = 1;
        }

        if ( byte_events )
        {
            // Check if the offset has a byte-event registered
            addr_t pa = (req->u.mem_access.gfn<<12) + req->u.mem_access.offset;
            vmi_event_t *byte_event = (vmi_event_t *)g_hash_table_lookup(byte_events, &pa);

            if(byte_event && (byte_event->mem_event.in_access & out_access))
            {
                byte_event->regs.x86 = (x86_registers_t *)&req->data.regs.x86;
                byte_event->vmm_pagetable_id = req->altp2m_idx;
                vmi->event_callback = 1;
                process_response( issue_mem_cb(vmi, byte_event, req, out_access), byte_event, rsp );
                vmi->event_callback = 0;
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
            if(VMI_FAILURE == process_unhandled_mem(vmi, page, req))
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
        req->u.mem_access.gfn, (req->u.mem_access.gfn<<12) + req->u.mem_access.offset, out_access);

errdone:
    return VMI_FAILURE;
}

status_t process_single_step_event(vmi_instance_t vmi,
                                   vm_event_request_t *req,
                                   vm_event_response_t *rsp)
{
    xc_interface * xch = xen_get_xchandle(vmi);
    domid_t dom = xen_get_domainid(vmi);

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);

        return VMI_FAILURE;
    }

    vmi_event_t * event = g_hash_table_lookup(vmi->ss_events, &req->vcpu_id);

    if (event)
    {
        event->ss_event.gfn = req->u.singlestep.gfn;
        event->ss_event.offset = req->data.regs.x86.rip & VMI_BIT_MASK(0,11);
        event->ss_event.gla = req->data.regs.x86.rip;
        event->regs.x86 = (x86_registers_t *)&req->data.regs.x86;
        event->vcpu_id = req->vcpu_id;

        vmi->event_callback = 1;
        process_response ( event->callback(vmi, event), event, rsp );
        vmi->event_callback = 0;

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
    xc_interface * xch = xen_get_xchandle(vmi);
    xen_instance_t *xen = xen_get_instance(vmi);
    xen_events_t * xe = xen_get_events(vmi);
    domid_t dom = xen_get_domainid(vmi);

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

    rc = xc_set_mem_access(xch, dom, (mem_access_t)COMPAT_MEMACCESS_RWX, ~0ull, 0);
    rc = xc_set_mem_access(xch, dom, (mem_access_t)COMPAT_MEMACCESS_RWX, 0, xen->max_gpfn);
    rc = xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR0, false, false, false);
    rc = xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR3, false, false, false);
    rc = xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR4, false, false, false);
    rc = xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_XCR0, false, false, false);
    rc = xc_monitor_software_breakpoint(xch, dom, false);

    if ( xe->vm_event.ring_page ) {
        xen_events_listen(vmi, 0);
        munmap(xe->vm_event.ring_page, getpagesize());
    }

    if ( xc_monitor_disable(xch, dom) )
        errprint("Error disabling monitor vm_event ring.\n");

    // Unbind VIRQ
    if ( xe->vm_event.port > 0 )
        if ( xc_evtchn_unbind(xe->vm_event.xce_handle, xe->vm_event.port) )
            errprint("Error unbinding event port.\n");

    // Close event channel
    if ( xe->vm_event.xce_handle )
        if ( xc_evtchn_close(xe->vm_event.xce_handle) )
            errprint("Error closing event channel.\n");

    free(xe);
    xen_get_instance(vmi)->events = NULL;

    vmi_resume_vm(vmi);
}

status_t xen_events_init(vmi_instance_t vmi)
{
    xen_events_t * xe = NULL;
    xen_instance_t *xen = xen_get_instance(vmi);
    xc_interface * xch = xen_get_xchandle(vmi);
    xc_domaininfo_t dom_info = {0};
    domid_t dom = xen_get_domainid(vmi);
    unsigned long ring_pfn = 0;
    unsigned long mmap_pfn = 0;
    int rc;

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    // Allocate memory
    xe = g_malloc0(sizeof(xen_events_t));
    if ( !xe ) {
        errprint("%s error: allocation for xen_events_t failed\n", __FUNCTION__);
        goto err;
    }

    xen_get_instance(vmi)->events = xe;

    /* Enable monitor page */
    xe->vm_event.ring_page = xc_monitor_enable(xch, dom, &xe->vm_event.evtchn_port);
    if ( !xe->vm_event.ring_page )
    {
        switch ( errno ) {
            case EBUSY:
                errprint("vm_event is (or was) active on this domain\n");
                break;
            case ENODEV:
                errprint("vm_event is not supported for this guest\n");
                break;
            default:
                errprint("Error enabling vm_event\n");
                break;
        }
        goto err;
    }

    /* Open event channel */
    xe->vm_event.xce_handle = xc_evtchn_open(NULL, 0);
    if ( !xe->vm_event.xce_handle )
    {
        errprint("Failed to open event channel\n");
        goto err;
    }

    /* Bind event notification */
    rc = xc_evtchn_bind_interdomain(xe->vm_event.xce_handle,
                                    dom,
                                    xe->vm_event.evtchn_port);
    if ( rc < 0 ) {
        errprint("Failed to bind event channel\n");
        goto err;
    }

    xe->vm_event.port = rc;

    SHARED_RING_INIT((vm_event_sring_t *)xe->vm_event.ring_page);
    BACK_RING_INIT(&xe->vm_event.back_ring,
                   (vm_event_sring_t *)xe->vm_event.ring_page,
                   XC_PAGE_SIZE);

    /* Mem access events are always delivered via this ring */
    xe->vm_event.monitor_mem_access_on = 1;
    xc_monitor_get_capabilities(xch, dom, &xe->vm_event.monitor_capabilities);

    return VMI_SUCCESS;

err:
    return VMI_FAILURE;
}

status_t xen_set_reg_access(vmi_instance_t vmi, reg_event_t *event)
{
    bool enable;
    int rc;
    xc_interface * xch = xen_get_xchandle(vmi);
    domid_t dom = xen_get_domainid(vmi);
    xen_events_t * xe = xen_get_events(vmi);
    bool sync = !event->async;

    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        goto done;
    }

    if ( dom == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        goto done;
    }

    switch ( event->reg )
    {
        case CR0:
        case CR3:
        case CR4:
        case XCR0:
            if ( !(xe->vm_event.monitor_capabilities & (1u << XEN_DOMCTL_MONITOR_EVENT_WRITE_CTRLREG)) )
            {
                errprint("%s error: no system support for event type\n", __FUNCTION__);
                goto done;
            }
            break;

        case MSR_ALL:
            if ( !(xe->vm_event.monitor_capabilities & (1u << XEN_DOMCTL_MONITOR_EVENT_MOV_TO_MSR)) )
            {
                errprint("%s error: no system support for event type\n", __FUNCTION__);
                goto done;
            }
            break;
    }

    switch ( event->in_access )
    {
        case VMI_REGACCESS_N:
            enable = false;
            break;
        case VMI_REGACCESS_W:
            enable = true;
            break;
        case VMI_REGACCESS_R:
        case VMI_REGACCESS_RW:
            errprint("Register read events are unavailable in Xen.\n");
            goto done;
        default:
            errprint("Unknown register access mode: %d\n", event->in_access);
            goto done;
    }

    switch ( event->reg )
    {
        case CR0:
            if ( enable == xe->vm_event.monitor_cr0_on )
                goto done;

            rc = xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR0,
                                          enable, sync, event->onchange);
            if ( rc )
                goto done;

            xe->vm_event.monitor_cr0_on = enable;
            break;
        case CR3:
            if ( enable == xe->vm_event.monitor_cr3_on )
                goto done;

            rc = xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR3,
                                          enable, sync, event->onchange);
            if ( rc )
                goto done;

            xe->vm_event.monitor_cr3_on = enable;
            break;
        case CR4:
            if ( enable == xe->vm_event.monitor_cr4_on )
                goto done;

            rc = xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR4,
                                          enable, sync, event->onchange);
            if ( rc )
                goto done;

            xe->vm_event.monitor_cr4_on = enable;
        case XCR0:
            if ( enable == xe->vm_event.monitor_xcr0_on )
                goto done;

            rc = xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_XCR0,
                                          enable, sync, event->onchange);
            if ( rc )
                goto done;

            xe->vm_event.monitor_xcr0_on = enable;
            break;
        case MSR_ALL:
            if ( enable == xe->vm_event.monitor_msr_on )
                goto done;

            rc = xc_monitor_mov_to_msr(xch, dom, enable, event->extended_msr);
            if ( rc )
                goto done;

            xe->vm_event.monitor_msr_on = enable;
            break;
        default:
            errprint("Tried to register for unsupported register event.\n");
            goto done;
    }

    return VMI_SUCCESS;

done:
    return VMI_FAILURE;
}

status_t xen_set_mem_access(vmi_instance_t vmi, mem_access_event_t *event,
                            vmi_mem_access_t page_access_flag, uint16_t altp2m_idx)
{
    int rc;
    mem_access_t access;
    xen_instance_t *xen = xen_get_instance(vmi);
    xc_interface * xch = xen_get_xchandle(vmi);
    xen_events_t * xe = xen_get_events(vmi);
    domid_t dom = xen_get_domainid(vmi);

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

    uint64_t npages = page_key + event->npages > xen->max_gpfn
        ? xen->max_gpfn - page_key: event->npages;

    // Convert betwen vmi_mem_access_t and mem_access_t
    // Xen does them backwards....
    access = compat_memaccess_conversion[page_access_flag];

    dbprint(VMI_DEBUG_XEN, "--Setting memaccess for domain %"PRIu64" on physical address: %"PRIu64" npages: %"PRIu64"\n",
        dom, event->physical_address, npages);

    if ( !altp2m_idx )
        rc = xc_set_mem_access(xch, dom, access, page_key, npages);
    else
        rc = xc_altp2m_set_mem_access(xch, dom, altp2m_idx, page_key, access);

    if(rc) {
        errprint("xc_hvm_set_mem_access failed with code: %d\n", rc);
        return VMI_FAILURE;
    }
    dbprint(VMI_DEBUG_XEN, "--Done Setting memaccess on physical address: %"PRIu64"\n", event->physical_address);
    return VMI_SUCCESS;
}

status_t xen_set_intr_access(vmi_instance_t vmi, interrupt_event_t *event, bool enabled)
{

    switch ( event->intr )
    {
        case INT3:
            return xen_set_int3_access(vmi, enabled);
            break;
        default:
            errprint("Xen driver does not support enabling events for interrupt: %"PRIu32"\n", event->intr);
            break;
    }

    return VMI_FAILURE;
}

status_t xen_set_int3_access(vmi_instance_t vmi, bool enable)
{
    xc_interface * xch = xen_get_xchandle(vmi);
    domid_t dom = xen_get_domainid(vmi);
    xen_events_t *xe = xen_get_events(vmi);

    if ( !xch )
    {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( dom == VMI_INVALID_DOMID )
    {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( !(xe->vm_event.monitor_capabilities & (1u << XEN_DOMCTL_MONITOR_EVENT_SOFTWARE_BREAKPOINT)) )
    {
        errprint("%s error: no system support for event type\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( enable == xe->vm_event.monitor_intr_on )
        return VMI_FAILURE;

    if ( xc_monitor_software_breakpoint(xch, dom, enable) )
        return VMI_FAILURE;

    xe->vm_event.monitor_intr_on = enable;
    return VMI_SUCCESS;
}

status_t xen_start_single_step(vmi_instance_t vmi, single_step_event_t *event)
{
    domid_t dom = xen_get_domainid(vmi);
    xen_events_t *xe = xen_get_events(vmi);
    int rc;
    uint32_t i;

    if ( !(xe->vm_event.monitor_capabilities & (1u << XEN_DOMCTL_MONITOR_EVENT_SINGLESTEP)) )
    {
        errprint("%s error: no system support for event type\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    dbprint(VMI_DEBUG_XEN, "--Starting single step on domain %"PRIu64"\n", dom);

    if ( !xe->vm_event.monitor_singlestep_on )
    {
        rc = xc_monitor_singlestep(xen_get_xchandle(vmi), dom, true);
        if ( rc<0 )
        {
            errprint("Error %d setting HVM single step\n", rc);
            return VMI_FAILURE;
        }

        xe->vm_event.monitor_singlestep_on = 1;
    }

    /*
     * We only actually flip the MTF flag if the 'enable' option is specified.
     * This is necessariy if singlestep is used by flipping on the event_response_t option
     * as LibVMI needs to be able to catch and forward those events.
     */
    if ( event->vcpus && event->enable )
    {
        for(i=0 ; i < MAX_SINGLESTEP_VCPUS; i++)
        {
            if ( CHECK_VCPU_SINGLESTEP(*event, i) )
            {
                dbprint(VMI_DEBUG_XEN, "--Setting MTF flag on vcpu %u\n", i);

                if ( xen_set_domain_debug_control(vmi, i, 1) == VMI_FAILURE )
                {
                    errprint("Error setting MTF flag on vcpu %u\n", i);
                    goto rewind;
                }
            }
        }
    }

    return VMI_SUCCESS;

 rewind:
    do {
        xen_stop_single_step(vmi, i);
    } while (i--);

    return VMI_FAILURE;
}

status_t xen_stop_single_step(vmi_instance_t vmi, uint32_t vcpu)
{
    domid_t dom = xen_get_domainid(vmi);
    status_t ret = VMI_FAILURE;

    dbprint(VMI_DEBUG_XEN, "--Removing MTF flag from vcpu %u\n", vcpu);

    ret = xen_set_domain_debug_control(vmi, vcpu, 0);

    return ret;
}

status_t xen_shutdown_single_step(vmi_instance_t vmi) {
    domid_t dom = xen_get_domainid(vmi);
    xen_events_t *xe = xen_get_events(vmi);
    int rc = -1;
    uint32_t i=0;

    dbprint(VMI_DEBUG_XEN, "--Shutting down single step on domain %"PRIu64"\n", dom);

    for(;i<vmi->num_vcpus; i++) {
        xen_stop_single_step(vmi, i);
    }

    if ( xe->vm_event.monitor_singlestep_on )
    {
        rc = xc_monitor_singlestep(xen_get_xchandle(vmi), dom,false);

        if (rc<0) {
            errprint("Error %d disabling single step\n", rc);
            return VMI_FAILURE;
        }

        xe->vm_event.monitor_singlestep_on = 0;
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

    return RING_HAS_UNCONSUMED_REQUESTS(&xe->vm_event.back_ring);

}

static inline
status_t process_requests(vmi_instance_t vmi, vm_event_request_t *req,
                          vm_event_response_t *rsp)
{
    xen_events_t * xe = xen_get_events(vmi);
    status_t vrc = VMI_SUCCESS;

    while ( RING_HAS_UNCONSUMED_REQUESTS(&xe->vm_event.back_ring) ) {
        memset( req, 0, sizeof (req) );
        memset( rsp, 0, sizeof (rsp) );

        get_request(&xe->vm_event, req);

        if ( req->version != VM_EVENT_INTERFACE_VERSION )
        {
            errprint("Error, Xen reports a different VM_EVENT_INTERFACE_VERSION!\n");
            return VMI_FAILURE;
        }

        rsp->version = VM_EVENT_INTERFACE_VERSION;
        rsp->vcpu_id = req->vcpu_id;
        rsp->flags = (req->flags & VM_EVENT_FLAG_VCPU_PAUSED);
        rsp->reason = req->reason;

        /*
         * When we shut down we pull all pending requests from the ring
         */
        if ( vmi->shutting_down )
        {
            if ( req->reason == VM_EVENT_REASON_MEM_ACCESS )
                rsp->u.mem_access.gfn = req->u.mem_access.gfn;
        }
        else
        switch ( req->reason )
        {
            case VM_EVENT_REASON_MEM_ACCESS:
                dbprint(VMI_DEBUG_XEN, "--Caught mem access event!\n");
                vrc = process_mem(vmi, req, rsp);
                break;

            case VM_EVENT_REASON_WRITE_CTRLREG:
                switch ( req->u.write_ctrlreg.index )
                {
                    case VM_EVENT_X86_CR0:
                        dbprint(VMI_DEBUG_XEN, "--Caught MOV-TO-CR0 event!\n");
                        vrc = process_register(vmi, CR0, req, rsp);
                        break;

                    case VM_EVENT_X86_CR3:
                        dbprint(VMI_DEBUG_XEN, "--Caught MOV-TO-CR3 event!\n");
                        vrc = process_register(vmi, CR3, req, rsp);
                        break;

                    case VM_EVENT_X86_CR4:
                        dbprint(VMI_DEBUG_XEN, "--Caught MOV-TO-CR4 event!\n");
                        vrc = process_register(vmi, CR4, req, rsp);
                        break;

                    case VM_EVENT_X86_XCR0:
                        dbprint(VMI_DEBUG_XEN, "--Caught MOV-TO-XCR0 event!\n");
                        vrc = process_register(vmi, XCR0, req, rsp);
                        break;
                    default:
                        dbprint(VMI_DEBUG_XEN, "--Caught unknown WRITE_CTRLREG event!\n");
                        break;

                }
                break;

            case VM_EVENT_REASON_MOV_TO_MSR:
                dbprint(VMI_DEBUG_XEN, "--Caught MOV-TO-MSR event!\n");
                vrc = process_register(vmi, MSR_ALL, req, rsp);
                break;

            case VM_EVENT_REASON_SINGLESTEP:
                dbprint(VMI_DEBUG_XEN, "--Caught single step event!\n");
                vrc = process_single_step_event(vmi, req, rsp);
                break;

            case VM_EVENT_REASON_SOFTWARE_BREAKPOINT:
                dbprint(VMI_DEBUG_XEN, "--Caught int3 interrupt event!\n");
                vrc = process_interrupt_event(vmi, INT3, req, rsp);
                break;

            default:
                errprint("UNKNOWN REASON CODE %d\n", req->reason);
                vrc = VMI_FAILURE;
                break;
        }

        /*
         * Put the response on the ring
         */
        put_response(&xe->vm_event, rsp);
        dbprint(VMI_DEBUG_XEN, "--Finished handling event.\n");
    }

    return vrc;
}

status_t xen_events_listen(vmi_instance_t vmi, uint32_t timeout)
{
    vm_event_request_t req;
    vm_event_response_t rsp;
    xc_interface * xch = xen_get_xchandle(vmi);
    xen_events_t * xe = xen_get_events(vmi);
    domid_t dom = xen_get_domainid(vmi);

    int rc = -1;
    status_t vrc = VMI_SUCCESS;

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
        errprint("Error %d setting mem_access listener required to %d\n",
            rc, vmi->event_listener_required);
    }

    if(!vmi->shutting_down && timeout > 0) {
        dbprint(VMI_DEBUG_XEN, "--Waiting for xen events...(%"PRIu32" ms)\n", timeout);
        rc = wait_for_event_or_timeout(xch, xe->vm_event.xce_handle, timeout);
        if ( rc < -1 ) {
            errprint("Error while waiting for event.\n");
            return VMI_FAILURE;
        }
    }

    vrc = process_requests(vmi, &req, &rsp);

    /*
     * The only way to gracefully handle vmi_clear_event requests
     * that were issued in a callback is to ensure no more requests
     * are in the ringpage. We do this by pausing the domain (all vCPUs)
     * and process all reamining events on the ring. Once no more requests
     * are on the ring we can remove the events.
     */
    if ( g_hash_table_size(vmi->clear_events) ) {
        vmi_pause_vm(vmi); // Pause all vCPUs
        vrc = process_requests(vmi, &req, &rsp);

        GHashTableIter i;
        vmi_event_t **key = NULL;
        vmi_event_free_t cb;

        ghashtable_foreach(vmi->clear_events, i, &key, &cb) {
            vmi_clear_event(vmi, *key, cb);
        }

        g_hash_table_destroy(vmi->clear_events);
        vmi->clear_events =
            g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);

        vmi_resume_vm(vmi);
    }

    /*
     * We only resume the domain once all requests are processed from the ring
     */
    if ( resume_domain(vmi) )
    {
        errprint("Error resuming domain.\n");
        return VMI_FAILURE;
    }

    return vrc;
}

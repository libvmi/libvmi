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
static inline int get_mem_event_42(xen_mem_event_t *mem_event, mem_event_42_request_t *req)
{
    mem_event_42_back_ring_t *back_ring;
    RING_IDX req_cons;

    back_ring = &mem_event->back_ring_42;
    req_cons = back_ring->req_cons;

    // Copy request
    memcpy(req, RING_GET_REQUEST(back_ring, req_cons), sizeof(mem_event_42_request_t));
    req_cons++;

    // Update ring
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;

    return 0;
}

static inline int put_mem_response_42(xen_mem_event_t *mem_event, mem_event_42_response_t *rsp)
{
    mem_event_42_back_ring_t *back_ring;
    RING_IDX rsp_prod;

    back_ring = &mem_event->back_ring_42;
    rsp_prod = back_ring->rsp_prod_pvt;

    // Copy response
    memcpy(RING_GET_RESPONSE(back_ring, rsp_prod), rsp, sizeof(mem_event_42_response_t));
    rsp_prod++;

    // Update ring
    back_ring->rsp_prod_pvt = rsp_prod;
    RING_PUSH_RESPONSES(back_ring);

    return 0;
}

static inline void get_mem_event_45(xen_mem_event_t *mem_event, mem_event_45_request_t *req)
{
    mem_event_45_back_ring_t *back_ring;
    RING_IDX req_cons;

    back_ring = &mem_event->back_ring_45;
    req_cons = back_ring->req_cons;

    // Copy request
    memcpy(req, RING_GET_REQUEST(back_ring, req_cons), sizeof(mem_event_45_request_t));
    req_cons++;

    // Update ring
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;
}

static inline int put_mem_response_45(xen_mem_event_t *mem_event, mem_event_45_response_t *rsp)
{
    mem_event_45_back_ring_t *back_ring;
    RING_IDX rsp_prod;

    back_ring = &mem_event->back_ring_45;
    rsp_prod = back_ring->rsp_prod_pvt;

    // Copy response
    memcpy(RING_GET_RESPONSE(back_ring, rsp_prod), rsp, sizeof(mem_event_45_response_t));
    rsp_prod++;

    // Update ring
    back_ring->rsp_prod_pvt = rsp_prod;
    RING_PUSH_RESPONSES(back_ring);

    return 0;
}

static inline void process_response ( event_response_t response, uint32_t *rsp_flags )
{
    if ( !rsp_flags )
        return;

    if ( response & VMI_EVENT_RESPONSE_EMULATE )
        *rsp_flags |= MEM_EVENT_FLAG_EMULATE;
    if ( response & VMI_EVENT_RESPONSE_EMULATE_NOWRITE )
        *rsp_flags |= MEM_EVENT_FLAG_EMULATE_NOWRITE;
}

static
status_t process_interrupt_event(vmi_instance_t vmi, interrupts_t intr,
                                 uint64_t gfn, uint64_t offset, uint64_t gla, uint32_t vcpu_id,
                                 uint32_t *rsp_flags)
{

    int rc                      = -1;
    status_t status             = VMI_FAILURE;
    gint lookup                 = intr;
    vmi_event_t * event         = g_hash_table_lookup(vmi->interrupt_events, &lookup);
    xc_interface * xch          = xen_get_xchandle(vmi);
    unsigned long domain_id     = xen_get_domainid(vmi);
    xen_instance_t *xen         = xen_get_instance(vmi);


    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( domain_id == VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if (event) {
        event->interrupt_event.gfn = gfn;
        event->interrupt_event.offset = offset;
        event->interrupt_event.gla = gla;
        event->interrupt_event.intr = intr;
        event->interrupt_event.reinject = -1;
        event->vcpu_id = vcpu_id;

        /* Will need to refactor if another interrupt is accessible
         *  via events, and needs differing setup before callback.
         *  ..but this basic structure should be adequate for now.
         */

        vmi->event_callback = 1;
        process_response ( event->callback(vmi, event), rsp_flags );
        vmi->event_callback = 0;

        if (-1 == event->interrupt_event.reinject) {
            errprint("%s Need to specify reinjection behaviour!\n", __FUNCTION__);
            return VMI_FAILURE;
        }

        switch (intr) {
            case INT3:
                /* Reinject (callback may decide) */
                if (1 == event->interrupt_event.reinject) {
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
                    rc = xen->libxcw.xc_hvm_inject_trap(xch, domain_id, vcpu_id,
                                                        TRAP_int3,         /* Vector 3 for INT3 */
                                                        X86_TRAP_sw_exc,   /* Trap type, here a software intr */
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
                    /*
                     * Reinjection may return an error code when it actually worked
                     * NOTE: 4.2.3 has the required patch
                     *   i.e., 'fix HVMOP_inject_trap return value on success'
                     * But this cannot be inferred via __XEN_INTERFACE_VERSION__, which is only
                     *  updated for major versions.
                     */
                    if ( xen->major_version == 4 && xen->minor_version > 3 && rc < 0) {
                        errprint("%s : Xen event error %d re-injecting int3\n", __FUNCTION__, rc);
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

static
status_t process_register(vmi_instance_t vmi,
                          reg_t reg, uint64_t gfn, uint32_t vcpu_id, uint64_t gla,
                          uint32_t *rsp_flags)
{
    gint lookup         = reg;
    vmi_event_t * event = g_hash_table_lookup(vmi->reg_events, &lookup);
    xen_instance_t *xen = xen_get_instance(vmi);

    if (event) {
        /* reg_event.equal allows you to set a reg event for
         *  a specific VALUE of the register (passed in req.gfn)
         */
        if (event->reg_event.equal && event->reg_event.equal != gfn)
            return VMI_SUCCESS;

        event->reg_event.value = gfn;
        event->vcpu_id = vcpu_id;

        /* Copy CR0/CR3/CR4 old values, available from 4.4 */
        if (xen->major_version == 4 && xen->minor_version >= 4)
            switch (event->reg_event.reg) {
                case CR0:
                case CR3:
                case CR4:
                    event->reg_event.previous = gla;
                default:
                    break;
            };

        /* Special case: indicate which MSR is being written (passed in gla) */
        if (xen->major_version == 4 && xen->minor_version > 2 && event->reg_event.reg == MSR_ALL)
            event->reg_event.msr = gla;

        /* TODO MARESCA: note that vmi_event_t lacks a flags member
         *   so we have no req.flags equivalent. might need to add
         *   e.g !!(req.flags & MEM_EVENT_FLAG_VCPU_PAUSED)  would be nice
         */
        vmi->event_callback = 1;
        process_response ( event->callback(vmi, event), rsp_flags );
        vmi->event_callback = 0;

        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

static
status_t process_mem(vmi_instance_t vmi, bool access_r, bool access_w, bool access_x,
                     uint64_t gfn, uint64_t offset, bool gla_valid, uint64_t gla,
                     uint32_t vcpu_id, uint32_t *rsp_flags)
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

    vmi_event_t *event;
    vmi_mem_access_t out_access = VMI_MEMACCESS_INVALID;
    if (access_r) out_access |= VMI_MEMACCESS_R;
    if (access_w) out_access |= VMI_MEMACCESS_W;
    if (access_x) out_access |= VMI_MEMACCESS_X;

    if ( g_hash_table_size(vmi->mem_events_on_gfn) ) {
        event = g_hash_table_lookup(vmi->mem_events_on_gfn, &gfn);

        if (event && event->mem_event.in_access & out_access) {
            event->mem_event.gla_valid = gla_valid;
            event->mem_event.gla = gla_valid ? gla : 0ull;
            event->mem_event.gfn = gfn;
            event->mem_event.offset = offset;
            event->mem_event.out_access = out_access;
            event->vcpu_id = vcpu_id;

            vmi->event_callback = 1;
            process_response ( event->callback(vmi, event), rsp_flags );
            vmi->event_callback = 0;

            return VMI_SUCCESS;
        }
    }

    if ( g_hash_table_size(vmi->mem_events_generic) ) {
        GHashTableIter i;
        vmi_mem_access_t *key = NULL;
        bool cb_issued = 0;

        ghashtable_foreach(vmi->mem_events_generic, i, &key, &event) {
            if ( event->mem_event.in_access & out_access ) {
                event->mem_event.gla = gla_valid ? gla : ~0ull;
                event->mem_event.gfn = gfn;
                event->mem_event.offset = offset;
                event->mem_event.out_access = out_access;
                event->vcpu_id = vcpu_id;
                vmi->event_callback = 1;
                process_response ( event->callback(vmi, event), rsp_flags );
                vmi->event_callback = 0;
                cb_issued = 1;
            }
        }

        if ( cb_issued )
            return VMI_SUCCESS;
    }

    /*
     * TODO: Could this happen when using multi-vCPU VMs where multiple vCPU's trigger
     *       the same violation and the event is already being passed to vmi_step_event?
     *       The event in that case would be already removed from the GHashTable so
     *       the second violation on the other vCPU would not get delivered..
     */
    errprint("Caught a memory event that had no handler registered in LibVMI @ GFN %"PRIu64" (0x%"PRIx64"), access: %u\n",
             gfn, (gfn<<12) + offset, out_access);

    return VMI_FAILURE;
}

static
status_t process_single_step_event(vmi_instance_t vmi, uint64_t gfn, uint64_t gla, uint32_t vcpu_id, uint32_t *rsp_flags)
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

    vmi_event_t * event = g_hash_table_lookup(vmi->ss_events, &vcpu_id);

    if (event) {
        event->ss_event.gla = gla;
        event->ss_event.gfn = gfn;
        event->vcpu_id = vcpu_id;

        vmi->event_callback = 1;
        process_response ( event->callback(vmi, event), rsp_flags );
        vmi->event_callback = 0;

        return VMI_SUCCESS;
    }

    errprint("%s error: no singlestep handler is registered in LibVMI\n", __FUNCTION__);
    return VMI_FAILURE;
}

static status_t xen_set_int3_access(vmi_instance_t vmi, bool enabled)
{
    xen_instance_t *xen = xen_get_instance(vmi);
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

    return xen->libxcw.xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_INT3, param);
}

//----------------------------------------------------------------------------
// Driver functions

status_t xen_set_reg_access_legacy(vmi_instance_t vmi, reg_event_t *event)
{
    xen_instance_t *xen = xen_get_instance(vmi);
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

    switch (event->in_access) {
        case VMI_REGACCESS_N:
            break;
        case VMI_REGACCESS_W:
            value = HVMPME_mode_sync;
            if (event->async)
                value = HVMPME_mode_async;

            /* NOTE: this is completely ignored within Xen for MSR events */
            if (event->onchange)
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

    switch (event->reg) {
        case CR0:
            /* More info as to why:
             * http://xenbits.xen.org/gitweb/?p=xen.git;a=commit;h=5d570c1d0274cac3b333ef378af3325b3b69905e */
            if ( xen->minor_version >=2 && xen->minor_version <= 4 )
                errprint("The majority of events on CR0 are unavailable for Xen 4.2 - 4.4.\n");
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
    if (xen->libxcw.xc_set_hvm_param(xch, dom, hvm_param, value))
        return VMI_FAILURE;
    return VMI_SUCCESS;
}

status_t
xen_set_mem_access_legacy(vmi_instance_t vmi, addr_t gpfn,
                          vmi_mem_access_t page_access_flag, uint16_t UNUSED(vmm_pagetable_id))
{
    int rc;
    xc_interface * xch = xen_get_xchandle(vmi);
    xen_events_t * xe = xen_get_events(vmi);
    unsigned long dom = xen_get_domainid(vmi);
    xen_instance_t * xen = xen_get_instance(vmi);

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

    /*
     * Convert betwen vmi_mem_access_t and mem_access_t
     * Xen uses the actual page permissions while LibVMI
     * uses the required restriction.
     */
    if (xen->major_version == 4 && xen->minor_version < 5 ) {
        hvmmem_access_t access;
        if ( VMI_FAILURE == convert_vmi_flags_to_hvmmem(page_access_flag, &access) )
            return VMI_FAILURE;

        rc = xen->libxcw.xc_hvm_set_mem_access(xch, dom, access, gpfn, 1); // 1 page at a time
    } else {
        xenmem_access_t access;
        if ( VMI_FAILURE == convert_vmi_flags_to_xenmem(page_access_flag, &access) )
            return VMI_FAILURE;

        rc = xen->libxcw.xc_set_mem_access(xch, dom, access, gpfn, 1); // 1 page at a time
    }

    dbprint(VMI_DEBUG_XEN, "--Setting memaccess for domain %lu on GPFN: %"PRIu64"\n",
            dom, gpfn);

    if (rc) {
        errprint("xc_hvm_set_mem_access failed with code: %d\n", rc);
        return VMI_FAILURE;
    }
    dbprint(VMI_DEBUG_XEN, "--Done Setting memaccess on GPFN: %"PRIu64"\n", gpfn);
    return VMI_SUCCESS;
}

status_t xen_set_intr_access_legacy(vmi_instance_t vmi, interrupt_event_t *event, bool enabled)
{

    switch (event->intr) {
        case INT3:
            return xen_set_int3_access(vmi, enabled);
            break;
        default:
            errprint("Xen driver does not support enabling events for interrupt: %"PRIu32"\n", event->intr);
            break;
    }

    return VMI_FAILURE;
}

status_t xen_stop_single_step_legacy(vmi_instance_t vmi, uint32_t vcpu)
{
    status_t ret = VMI_FAILURE;

    dbprint(VMI_DEBUG_XEN, "--Removing MTF flag from vcpu %u\n", vcpu);

    ret = xen_set_domain_debug_control(vmi, vcpu, 0);

    return ret;
}

status_t xen_start_single_step_legacy(vmi_instance_t vmi, single_step_event_t *event)
{
    unsigned long dom = xen_get_domainid(vmi);
    int rc = -1;
    uint32_t i = 0;
    xen_instance_t *xen = xen_get_instance(vmi);

    dbprint(VMI_DEBUG_XEN, "--Starting single step on domain %lu\n", dom);

    rc = xen->libxcw.xc_set_hvm_param(
             xen_get_xchandle(vmi), dom,
             HVM_PARAM_MEMORY_EVENT_SINGLE_STEP, HVMPME_mode_sync);

    if (rc<0) {
        errprint("Error %d setting HVM single step\n", rc);
        return VMI_FAILURE;
    }

    for (; i < MAX_SINGLESTEP_VCPUS; i++) {
        if (CHECK_VCPU_SINGLESTEP(*event, i)) {
            dbprint(VMI_DEBUG_XEN, "--Setting MTF flag on vcpu %u\n", i);
            if (xen_set_domain_debug_control(vmi, i, 1) == VMI_FAILURE) {
                errprint("Error setting MTF flag on vcpu %u\n", i);
                goto rewind;
            }
        }
    }

    return VMI_SUCCESS;

rewind:
    do {
        xen_stop_single_step_legacy(vmi, i);
    } while (i--);

    return VMI_FAILURE;
}

status_t xen_shutdown_single_step_legacy(vmi_instance_t vmi)
{
    unsigned long dom = xen_get_domainid(vmi);
    int rc = -1;
    uint32_t i=0;
    xen_instance_t *xen =xen_get_instance(vmi);

    dbprint(VMI_DEBUG_XEN, "--Shutting down single step on domain %lu\n", dom);

    for (; i<vmi->num_vcpus; i++) {
        xen_stop_single_step_legacy(vmi, i);
    }

    rc = xen->libxcw.xc_set_hvm_param(
             xen_get_xchandle(vmi), dom,
             HVM_PARAM_MEMORY_EVENT_SINGLE_STEP, HVMPME_mode_disabled);

    if (rc<0) {
        errprint("Error %d disabling HVM single step\n", rc);
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

int xen_are_events_pending_42(vmi_instance_t vmi)
{
    xen_events_t *xe = xen_get_events(vmi);

    if ( !xe ) {
        errprint("%s error: invalid xen_events_t handle\n", __FUNCTION__);
        return -1;
    }

    return RING_HAS_UNCONSUMED_REQUESTS(&xe->mem_event.back_ring_42);

}

int xen_are_events_pending_45(vmi_instance_t vmi)
{
    xen_events_t *xe = xen_get_events(vmi);

    if ( !xe ) {
        errprint("%s error: invalid xen_events_t handle\n", __FUNCTION__);
        return -1;
    }

    return RING_HAS_UNCONSUMED_REQUESTS(&xe->mem_event.back_ring_45);
}

status_t xen_events_listen_42(vmi_instance_t vmi, uint32_t timeout)
{
    xc_interface * xch = xen_get_xchandle(vmi);
    xen_events_t * xe = xen_get_events(vmi);
    unsigned long dom = xen_get_domainid(vmi);
    xen_instance_t *xen = xen_get_instance(vmi);
    mem_event_42_request_t req;
    mem_event_42_response_t rsp;

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

    if (!vmi->shutting_down && timeout > 0) {
        dbprint(VMI_DEBUG_XEN, "--Waiting for xen events...(%"PRIu32" ms)\n", timeout);
        if ( VMI_FAILURE == wait_for_event_or_timeout(xen, xe->mem_event.xce_handle, timeout) ) {
            errprint("Error while waiting for event.\n");
            return VMI_FAILURE;
        }
    }

    while ( RING_HAS_UNCONSUMED_REQUESTS(&xe->mem_event.back_ring_42) ) {
        rc = get_mem_event_42(&xe->mem_event, &req);
        if ( rc != 0 ) {
            errprint("Error getting event.\n");
            return VMI_FAILURE;
        }

        memset( &rsp, 0, sizeof (rsp) );
        rsp.vcpu_id = req.vcpu_id;
        rsp.flags = req.flags;

        switch (req.reason) {
            case MEM_EVENT_REASON_VIOLATION:
                dbprint(VMI_DEBUG_XEN, "--Caught mem event!\n");
                rsp.gfn = req.gfn;

                if (!vmi->shutting_down) {
                    vrc = process_mem(vmi, req.access_r, req.access_w, req.access_x,
                                      req.gfn, req.offset, req.gla_valid, req.gla,
                                      req.vcpu_id, NULL);
                }

                /*MARESCA do we need logic here to reset flags on a page? see xen-access.c
                 *    specifically regarding write/exec/int3 inspection and the code surrounding
                 *    the variables default_access and after_first_access
                 */

                break;
            case MEM_EVENT_REASON_CR0:
                dbprint(VMI_DEBUG_XEN, "--Caught CR0 event!\n");
                if (!vmi->shutting_down) {
                    vrc = process_register(vmi, CR0, req.gfn, req.gla, req.vcpu_id, NULL);
                }
                break;
            case MEM_EVENT_REASON_CR3:
                dbprint(VMI_DEBUG_XEN, "--Caught CR3 event!\n");
                if (!vmi->shutting_down) {
                    vrc = process_register(vmi, CR3, req.gfn, req.gla, req.vcpu_id, NULL);
                }
                break;
#ifdef HVM_PARAM_MEMORY_EVENT_MSR
            case MEM_EVENT_REASON_MSR:
                if (!vmi->shutting_down) {
                    dbprint(VMI_DEBUG_XEN, "--Caught MSR event!\n");
                    vrc = process_register(vmi, MSR_ALL, req.gfn, req.gla, req.vcpu_id, NULL);
                }
                break;
#endif
            case MEM_EVENT_REASON_CR4:
                dbprint(VMI_DEBUG_XEN, "--Caught CR4 event!\n");
                if (!vmi->shutting_down) {
                    vrc = process_register(vmi, CR4, req.gfn, req.gla, req.vcpu_id, NULL);
                }
                break;
            case MEM_EVENT_REASON_SINGLESTEP:
                dbprint(VMI_DEBUG_XEN, "--Caught single step event!\n");
                if (!vmi->shutting_down) {
                    vrc = process_single_step_event(vmi, req.gfn, req.gla, req.vcpu_id, NULL);
                }
                break;
            case MEM_EVENT_REASON_INT3:
                if (!vmi->shutting_down) {
                    dbprint(VMI_DEBUG_XEN, "--Caught int3 interrupt event!\n");
                    vrc = process_interrupt_event(vmi, INT3, req.gfn, req.offset, req.gla, req.vcpu_id, NULL);
                }
                break;
            default:
                errprint("UNKNOWN REASON CODE %d\n", req.reason);
                vrc = VMI_FAILURE;
                break;
        }

        // Put the response on the ring
        rc = put_mem_response_42(&xe->mem_event, &rsp);
        if ( rc != 0 ) {
            errprint("Error putting event response on the ring.\n");
            return VMI_FAILURE;
        }

        dbprint(VMI_DEBUG_XEN, "--Finished handling event.\n");
    }

    // We only resume the domain once all requests are processed from the ring
    rc = xen->libxcw.xc_evtchn_notify(xe->mem_event.xce_handle, xe->mem_event.port);
    if ( rc ) {
        errprint("Error resuming domain.\n");
        return VMI_FAILURE;
    }

    return vrc;
}

/*
 * Only needed for Xen 4.5+ for VM state syncronization with multiple vCPUs.
 */
static inline status_t
process_requests_45(vmi_instance_t vmi, mem_event_45_request_t *req, mem_event_45_request_t *rsp)
{
    xen_events_t * xe = xen_get_events(vmi);
    status_t vrc = VMI_SUCCESS;
    int rc;

    while ( RING_HAS_UNCONSUMED_REQUESTS(&xe->mem_event.back_ring_45) ) {
        get_mem_event_45(&xe->mem_event, req);

        memset( rsp, 0, sizeof (mem_event_45_request_t) );
        rsp->vcpu_id = req->vcpu_id;
        rsp->flags = req->flags;

        switch (req->reason) {
            case MEM_EVENT_REASON_VIOLATION:
                dbprint(VMI_DEBUG_XEN, "--Caught mem event!\n");
                rsp->gfn = req->gfn;

                /*
                 * We need to copy back the violation type for emulation to work.
                 * It doesn't affect anything else if emulation flags are not set so it's safe
                 * to just do it in any case.
                 */
                rsp->access_r = req->access_r;
                rsp->access_w = req->access_w;
                rsp->access_x = req->access_x;

                if (!vmi->shutting_down) {
                    vrc = process_mem(vmi, req->access_r, req->access_w, req->access_x,
                                      req->gfn, req->offset, req->gla_valid, req->gla,
                                      req->vcpu_id, &rsp->flags);
                }

                /*MARESCA do we need logic here to reset flags on a page? see xen-access.c
                 *    specifically regarding write/exec/int3 inspection and the code surrounding
                 *    the variables default_access and after_first_access
                 */

                break;
            case MEM_EVENT_REASON_CR0:
                dbprint(VMI_DEBUG_XEN, "--Caught CR0 event!\n");
                if (!vmi->shutting_down) {
                    vrc = process_register(vmi, CR0, req->gfn, req->gla, req->vcpu_id, &rsp->flags);
                }
                break;
            case MEM_EVENT_REASON_CR3:
                dbprint(VMI_DEBUG_XEN, "--Caught CR3 event!\n");
                if (!vmi->shutting_down) {
                    vrc = process_register(vmi, CR3, req->gfn, req->gla, req->vcpu_id, &rsp->flags);
                }
                break;
            case MEM_EVENT_REASON_MSR:
                if (!vmi->shutting_down) {
                    dbprint(VMI_DEBUG_XEN, "--Caught MSR event!\n");
                    vrc = process_register(vmi, MSR_ALL, req->gfn, req->gla, req->vcpu_id, &rsp->flags);
                }
                break;
            case MEM_EVENT_REASON_CR4:
                dbprint(VMI_DEBUG_XEN, "--Caught CR4 event!\n");
                if (!vmi->shutting_down) {
                    vrc = process_register(vmi, CR4, req->gfn, req->gla, req->vcpu_id, &rsp->flags);
                }
                break;
            case MEM_EVENT_REASON_SINGLESTEP:
                dbprint(VMI_DEBUG_XEN, "--Caught single step event!\n");
                if (!vmi->shutting_down) {
                    vrc = process_single_step_event(vmi, req->gfn, req->gla, req->vcpu_id, &rsp->flags);
                }
                break;
            case MEM_EVENT_REASON_INT3:
                if (!vmi->shutting_down) {
                    dbprint(VMI_DEBUG_XEN, "--Caught int3 interrupt event!\n");
                    vrc = process_interrupt_event(vmi, INT3, req->gfn, req->offset, req->gla, req->vcpu_id, &rsp->flags);
                }
                break;
            default:
                errprint("UNKNOWN REASON CODE %d\n", req->reason);
                vrc = VMI_FAILURE;
                break;
        }

        // Put the response on the ring
        rc = put_mem_response_45(&xe->mem_event, rsp);
        if ( rc != 0 ) {
            errprint("Error putting event response on the ring.\n");
            return VMI_FAILURE;
        }

        dbprint(VMI_DEBUG_XEN, "--Finished handling event.\n");
    }

    return vrc;
}

status_t xen_events_listen_45(vmi_instance_t vmi, uint32_t timeout)
{
    xc_interface * xch = xen_get_xchandle(vmi);
    xen_events_t *xe = xen_get_events(vmi);
    unsigned long dom = xen_get_domainid(vmi);
    xen_instance_t *xen = xen_get_instance(vmi);

    mem_event_45_request_t req;
    mem_event_45_response_t rsp;

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

    if (!vmi->shutting_down && timeout > 0) {
        dbprint(VMI_DEBUG_XEN, "--Waiting for xen events...(%"PRIu32" ms)\n", timeout);
        if ( VMI_FAILURE == wait_for_event_or_timeout(xen, xe->mem_event.xce_handle, timeout) ) {
            errprint("Error while waiting for event.\n");
            return VMI_FAILURE;
        }
    }

    vrc = process_requests_45(vmi, &req, &rsp);

    /*
     * The only way to gracefully handle vmi_clear_event requests
     * that were issued in a callback is to ensure no more requests
     * are in the ringpage. We do this by pausing the domain (all vCPUs)
     * and process all reamining events on the ring. Once no more requests
     * are on the ring we can remove the events.
     */
    if ( vmi->clear_events && g_hash_table_size(vmi->clear_events) ) {
        vmi_pause_vm(vmi); // Pause all vCPUs
        vrc = process_requests_45(vmi, &req, &rsp);

        g_hash_table_foreach_remove(vmi->clear_events, clear_events_full, vmi);

        vmi_resume_vm(vmi);
    }

    // We only resume the domain once all requests are processed from the ring
    rc = xen->libxcw.xc_evtchn_notify(xe->mem_event.xce_handle, xe->mem_event.port);
    if ( rc ) {
        errprint("Error resuming domain.\n");
        return VMI_FAILURE;
    }

    return vrc;
}

void xen_events_destroy_legacy(vmi_instance_t vmi)
{
    int rc;
    xc_interface * xch;
    xen_events_t * xe;
    unsigned long dom;
    xen_instance_t *xen;

    // Get xen handle and domain.
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);
    xe = xen_get_events(vmi);
    xen = xen_get_instance(vmi);

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
    xen_shutdown_single_step_legacy(vmi);

    /* Unregister for all events */
    if ( xen->major_version == 4 && xen->minor_version < 5 ) {
        /* HVMMEM_* and xc_hvm_set_mem_access was used before 4.5 */
        (void)xen->libxcw.xc_hvm_set_mem_access(xch, dom, HVMMEM_access_rwx, ~0ull, 0);
        (void)xen->libxcw.xc_hvm_set_mem_access(xch, dom, HVMMEM_access_rwx, 0, xe->mem_event.max_pages);
    } else {
        /* XENMEM_* and xc_set_mem_access are used from 4.5 onwards */
        (void)xen->libxcw.xc_set_mem_access(xch, dom, XENMEM_access_rwx, ~0ull, 0);
        (void)xen->libxcw.xc_set_mem_access(xch, dom, XENMEM_access_rwx, 0, xe->mem_event.max_pages);
    }
    (void)xen->libxcw.xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_INT3, HVMPME_mode_disabled);
    (void)xen->libxcw.xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_CR0, HVMPME_mode_disabled);
    (void)xen->libxcw.xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_CR3, HVMPME_mode_disabled);
    (void)xen->libxcw.xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_CR4, HVMPME_mode_disabled);
    (void)xen->libxcw.xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_SINGLE_STEP, HVMPME_mode_disabled);

    /* MSR events got introduced in 4.2 */
    if ( xen->major_version == 4 && xen->minor_version > 2 )
        (void)xen->libxcw.xc_set_hvm_param(xch, dom, HVM_PARAM_MEMORY_EVENT_MSR, HVMPME_mode_disabled);

    if ( xen->major_version == 4 && xen->minor_version < 5 )
        xen_events_listen_42(vmi, 0);
    else
        xen_events_listen_45(vmi, 0);

    // Turn off mem events
    munmap(xe->mem_event.ring_page, getpagesize());
    rc = xen->libxcw.xc_mem_access_disable(xch, dom);

    if ( rc != 0 ) {
        errprint("Error disabling mem events.\n");
    }

    /* TODO MARESCA - might want the evtchn_bind flag like in xen-access here
     * for when this function is called before it was bound
     */
    // Unbind VIRQ
    rc = xen->libxcw.xc_evtchn_unbind(xe->mem_event.xce_handle, xe->mem_event.port);
    if ( rc != 0 ) {
        errprint("Error unbinding event port\n");
    }
    //xe->mem_event.port = -1;

    // Close event channel
    rc = xen->libxcw.xc_evtchn_close(xe->mem_event.xce_handle);
    if ( rc != 0 ) {
        errprint("Error closing event channel\n");
    }
    //xe->mem_event.xce_handle = NULL;

    free(xe);
    xen_get_instance(vmi)->events = NULL;

    vmi_resume_vm(vmi);
}

status_t xen_init_events_legacy(
    vmi_instance_t vmi,
    uint32_t init_flags,
    void *init_data)
{
    xen_events_t * xe = NULL;
    xc_interface * xch = NULL;
    xc_domaininfo_t dom_info = {0};
    xen_instance_t *xen = xen_get_instance(vmi);
    unsigned long dom = 0;
    unsigned long ring_pfn = 0;
    unsigned long mmap_pfn = 0;
    int rc = 0;

    /* Xen (as of 4.3) only supports events for HVM domains
     *  This is likely to expand to PV in the future, but
     *  until such time, enforce this restriction
     */
    if (vmi->vm_type != HVM) {
        errprint("Xen events: only HVM domains are supported.\n");
        return VMI_FAILURE;
    }

    /*
     * Wire up the functions
     * The ABI has changed between 4.2 and 4.5 so we need to account for that
     */
    if ( xen->major_version == 4 && xen->minor_version < 5 ) {
        vmi->driver.events_listen_ptr = &xen_events_listen_42;
        vmi->driver.are_events_pending_ptr = &xen_are_events_pending_42;
    } else {
        vmi->driver.events_listen_ptr = &xen_events_listen_45;
        vmi->driver.are_events_pending_ptr = &xen_are_events_pending_45;
    }

    vmi->driver.set_reg_access_ptr = &xen_set_reg_access_legacy;
    vmi->driver.set_intr_access_ptr = &xen_set_intr_access_legacy;
    vmi->driver.set_mem_access_ptr = &xen_set_mem_access_legacy;
    vmi->driver.start_single_step_ptr = &xen_start_single_step_legacy;
    vmi->driver.stop_single_step_ptr = &xen_stop_single_step_legacy;
    vmi->driver.shutdown_single_step_ptr = &xen_shutdown_single_step_legacy;

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

    xen->events = xe;

    dbprint(VMI_DEBUG_XEN, "Init xen events with xch == %llx\n", (unsigned long long)xch);

    rc = xen->libxcw.xc_domain_getinfolist(xch, dom, 1, &dom_info);
    if ( rc != 1 ) {
        errprint("Error getting domain info\n");
        goto err;
    }

    if (!(dom_info.flags & XEN_DOMINF_paused) && VMI_FAILURE == vmi_pause_vm(vmi)) {
        errprint("Failed to pause VM\n");
        goto err;
    }

    // This is mostly nice for setting global access.
    // There may be a better way to manage this.
    xe->mem_event.max_pages = dom_info.max_pages;

    /* Initialize the shared pages and enable mem events */
    int tries = 0;

    /* Initialization changed between 4.2 and 4.5 */
    if ( xen->major_version == 4 && xen->minor_version < 5 ) {
        /* Xen 4.2-4.4 initialization */

        // Initialise shared page
        xen->libxcw.xc_get_hvm_param(xch, dom, HVM_PARAM_ACCESS_RING_PFN, &ring_pfn);
        mmap_pfn = ring_pfn;
        xe->mem_event.ring_page =
            xen->libxcw.xc_map_foreign_batch(xch, dom, PROT_READ | PROT_WRITE, &mmap_pfn, 1);
        if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB ) {
            /* Map failed, populate ring page */
            rc = xen->libxcw.xc_domain_populate_physmap_exact(xch,
                    dom,
                    1, 0, 0, &ring_pfn);
            if ( rc != 0 ) {
                errprint("Failed to populate ring gfn\n");
                goto err;
            }

            mmap_pfn = ring_pfn;
            xe->mem_event.ring_page =
                xen->libxcw.xc_map_foreign_batch(xch, dom,
                                                 PROT_READ | PROT_WRITE, &mmap_pfn, 1);
            if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB ) {
                errprint("Could not map the ring page\n");
                goto err;
            }
        }
enable_42:
        rc = xen->libxcw.xc_mem_access_enable(xch, dom, &(xe->mem_event.evtchn_port));
        goto enable_done;

reinit_42:
        xen->libxcw.xc_mem_access_disable(xch, dom);
        goto enable_42;

    } else {
        /* Xen 4.5 initialization */

enable_45:
        /* Enable mem access and map the ring page */
        xe->mem_event.ring_page =
            xen->libxcw.xc_mem_access_enable2(xch, dom, &(xe->mem_event.evtchn_port));

        rc = xe->mem_event.ring_page ? 0 : 1;
        goto enable_done;

reinit_45:
        xen->libxcw.xc_mem_access_disable(xch, dom);
        goto enable_45;
    }

enable_done:
    if ( rc != 0 ) {
        switch ( errno ) {
            case EBUSY:
                errprint("events are (or were) active on this domain\n");
                if (!tries) {
                    errprint("trying to disable and re-enable events\n");
                    tries++;

                    if ( xen->major_version == 4 && xen->minor_version < 5 )
                        goto reinit_42;
                    else
                        goto reinit_45;
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

    /* Now that the ring is set, remove it from the guest's physmap */
    if ( xen->major_version == 4 && xen->minor_version > 1 && xen->minor_version < 5 &&
            xen->libxcw.xc_domain_decrease_reservation_exact(xch, dom, 1, 0, &ring_pfn) ) {
        errprint("Failed to remove ring from guest physmap\n");
        goto err;
    }

    if ( init_flags & VMI_INIT_XEN_EVTCHN )
        xe->mem_event.xce_handle = init_data;
    else {
        /* Open event channel */
        xe->mem_event.xce_handle = xen->libxcw.xc_evtchn_open(NULL, 0);
        if ( !xe->vm_event.xce_handle ) {
            errprint("Failed to open event channel\n");
            goto err;
        }
    }

    // Bind event notification
    rc = xen->libxcw.xc_evtchn_bind_interdomain(xe->mem_event.xce_handle, dom, xe->mem_event.evtchn_port);
    if ( rc < 0 ) {
        errprint("Failed to bind event channel\n");
        goto err;
    }

    xe->mem_event.port = rc;
    dbprint(VMI_DEBUG_XEN, "Bound to event channel on port == %d\n", xe->mem_event.port);

    /*
     * Initialise the ring according to the correct ABI
     */
    if ( xen->major_version == 4 && xen->minor_version < 5 ) {
        BACK_RING_INIT(&xe->mem_event.back_ring_42,
                       (mem_event_42_sring_t *)xe->mem_event.ring_page,
                       getpagesize());
    } else {
        BACK_RING_INIT(&xe->mem_event.back_ring_45,
                       (mem_event_45_sring_t *)xe->mem_event.ring_page,
                       getpagesize());
    }

    if (!(dom_info.flags & XEN_DOMINF_paused)) {
        vmi_resume_vm(vmi);
    }
    return VMI_SUCCESS;

err:
    errprint("Failed initialize xen events.\n");
    xen_events_destroy_legacy(vmi);

    if (!(dom_info.flags & XEN_DOMINF_paused)) {
        vmi_resume_vm(vmi);
    }
    return VMI_FAILURE;
}

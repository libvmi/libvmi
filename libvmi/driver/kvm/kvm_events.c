/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Mathieu Tarral (mathieu.tarral@ssi.gouv.fr)
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
#include <assert.h>

#include "private.h"
#include "msr-index.h"
#include "arch/intel.h"
#include "kvm.h"
#include "kvm_events.h"
#include "kvm_private.h"


// helper struct for process_cb_response_emulate to avoid ugly
// pointer arithmetic to find back pf field in process_cb_response_emulate()
struct kvm_event_pf_reply_packet {
    struct kvmi_vcpu_hdr hdr;
    struct kvmi_event_reply common;
    struct kvmi_event_pf_reply pf;
};

// start singlestep on a single VCPU
status_t
kvm_start_single_step_vcpu(
    vmi_instance_t vmi,
    uint32_t vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    assert(vcpu < vmi->num_vcpus);
    // toggle singlestepping
    dbprint(VMI_DEBUG_KVM, "--Setting MTF flag on vcpu %" PRIu32 "\n", vcpu);
    if (kvm->libkvmi.kvmi_control_singlestep(kvm->kvmi_dom, vcpu, true)) {
        errprint("%s: kvmi_control_singlestep failed: %s\n", __func__, strerror(errno));
        kvm->sstep_enabled[vcpu] = false;
        return VMI_FAILURE;
    }

    kvm->sstep_enabled[vcpu] = true;

    return VMI_SUCCESS;
}

// helper function to wait and pop the next event from the queue
status_t
kvm_get_next_event(
    kvm_instance_t *kvm,
    struct kvmi_dom_event **event,
    kvmi_timeout_t timeout)
{
    // wait next event
    if (kvm->libkvmi.kvmi_wait_event(kvm->kvmi_dom, timeout)) {
        if (errno == ETIMEDOUT) {
            // no events !
            return VMI_SUCCESS;
        }
        errprint("%s: kvmi_wait_event failed: %s\n", __func__, strerror(errno));
        return VMI_FAILURE;
    }

    // pop event from queue
    if (kvm->libkvmi.kvmi_pop_event(kvm->kvmi_dom, event)) {
        errprint("%s: kvmi_pop_event failed: %s\n", __func__, strerror(errno));
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}


/*
 * handle emulation related event response.
 * since only memory events support this feature, we can't
 * handle it in the common function
 */
static status_t
process_cb_response_emulate(
    vmi_instance_t vmi,
    event_response_t response,
    vmi_event_t *libvmi_event,
    struct kvm_event_pf_reply_packet* rpl)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm or kvmi handles\n", __func__);
        return VMI_FAILURE;
    }
    if (!libvmi_event || !rpl) {
        errprint("%s: invalid libvmi/rpl handles\n", __func__);
        return VMI_FAILURE;
    }
#endif
    status_t status = VMI_SUCCESS;

    // loop over all possible responses
    // only handle emulation, since only memory event are capable of that
    for (uint32_t i = VMI_EVENT_RESPONSE_NONE+1; i <=__VMI_EVENT_RESPONSE_MAX; i++) {
        event_response_t candidate = 1u << i;
        if (response & candidate) {
            switch (candidate) {
                case VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA:
                    if (libvmi_event->emul_read) {
                        if (libvmi_event->emul_read->size > sizeof(rpl->pf.ctx_data)) {
                            errprint("%s: requested emulation buffer size too big (max: %ld)\n", __func__, sizeof(rpl->pf.ctx_data));
                            status = VMI_FAILURE;
                        } else {
                            // set reply size
                            rpl->pf.ctx_size = libvmi_event->emul_read->size;
                            // set linear address
                            // TODO: ARM support
                            rpl->pf.ctx_addr = libvmi_event->mem_event.gla;
                            // copy libvmi buffer into kvm reply event
                            memcpy(rpl->pf.ctx_data, libvmi_event->emul_read->data, libvmi_event->emul_read->size);
                        }
                        // free ?
                        if (!libvmi_event->emul_read->dont_free) {
                            free(libvmi_event->emul_read);
                            libvmi_event->emul_read = NULL;
                        }
                    }
                    break;
            }
        }
    }

    return status;
}

static status_t
process_cb_response(
    vmi_instance_t vmi,
    event_response_t response,
    vmi_event_t *libvmi_event,
    struct kvmi_dom_event *kvmi_event,
    void *rpl,
    size_t rpl_size)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm or kvmi handles\n", __func__);
        return VMI_FAILURE;
    }
    // Note: libvmi_event can be NULL
    // this indicates that we are shutting down libvmi, and that vmi_events_listen(0) has been called
    // to process the rest of the events in the queue.
    // the libvmi event has already been cleared at this point.
    if (!kvmi_event || !rpl) {
        errprint("%s: invalid kvmi/rpl handles\n", __func__);
        return VMI_FAILURE;
    }
#endif

    unsigned int vcpu = kvmi_event->event.common.vcpu;
    assert(vcpu < vmi->num_vcpus);
    status_t status = VMI_FAILURE;
    registers_t regs = {0};

    // loop over all possible responses
    for (uint32_t i = VMI_EVENT_RESPONSE_NONE+1; i <=__VMI_EVENT_RESPONSE_MAX; i++) {
        event_response_t candidate = 1u << i;
        // skip VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA which is handled only for mem_events
        if (candidate == VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA)
            continue;
        if (response & candidate) {
            switch (candidate) {
                case VMI_EVENT_RESPONSE_SET_REGISTERS:
                    regs.x86 = (*libvmi_event->x86_regs);
                    if (VMI_FAILURE == kvm_set_vcpuregs(vmi, &regs, libvmi_event->vcpu_id)) {
                        errprint("%s: KVM: failed to set registers in callback response\n", __func__);
                        return VMI_FAILURE;
                    }
                    break;
                case VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP:
                    if (kvm->sstep_enabled[vcpu]) {
                        // disable
                        status = kvm_stop_single_step(vmi, vcpu);
                    } else {
                        // enable
                        status = kvm_start_single_step_vcpu(vmi, vcpu);
                    }
                    if (status == VMI_FAILURE) {
                        errprint("--Failed to toggle singlestep on VCPU %u\n", vcpu);
                        return VMI_FAILURE;
                    }
                    break;
                default:
                    errprint("%s: KVM - unhandled event reponse %u\n", __func__, candidate);
                    break;
            }
        }
    }

    if (kvm->libkvmi.kvmi_reply_event(kvm->kvmi_dom, kvmi_event->seq, rpl, rpl_size))
        return VMI_FAILURE;

    return VMI_SUCCESS;
}

static event_response_t
call_event_callback(
    vmi_instance_t vmi,
    vmi_event_t *libvmi_event)
{
    event_response_t response;
    vmi->event_callback = 1;
    response = libvmi_event->callback(vmi, libvmi_event);
    vmi->event_callback = 0;
    return response;
}

/*
 * VM event handlers (process_xxx)
 * called from kvm_events_listen
 */
static status_t
process_register(vmi_instance_t vmi, struct kvmi_dom_event *kvmi_event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !kvmi_event) {
        errprint("%s: Invalid vmi or kvmi event handles\n", __func__);
        return VMI_FAILURE;
    }
#endif
    dbprint(VMI_DEBUG_KVM, "--Received CR event\n");

    // associate kvmi reg -> libvmi reg
    reg_t libvmi_reg;
    switch (kvmi_event->event.cr.cr) {
        case 0:
            libvmi_reg = CR0;
            break;
        case 3:
            libvmi_reg = CR3;
            break;
        case 4:
            libvmi_reg = CR4;
            break;
        default:
            errprint("Unexpected CR value %" PRIu16 "\n", kvmi_event->event.cr.cr);
            return VMI_FAILURE;
    }

    // lookup vmi event
    vmi_event_t *libvmi_event = g_hash_table_lookup(vmi->reg_events, GSIZE_TO_POINTER(libvmi_reg));
    if (!libvmi_event) {
        errprint("%s: No control register event handler is registered in LibVMI\n", __func__);
        return VMI_FAILURE;
    }

    // fill libvmi_event struct
    x86_registers_t regs = {0};
    libvmi_event->x86_regs = &regs;

    struct kvm_regs *kvmi_regs = &kvmi_event->event.common.arch.regs;
    struct kvm_sregs *kvmi_sregs = &kvmi_event->event.common.arch.sregs;
    kvmi_regs_to_libvmi(kvmi_regs, kvmi_sregs, libvmi_event->x86_regs);
    libvmi_event->vcpu_id = kvmi_event->event.common.vcpu;

    // fill specific CR fields
    // TODO: kvmi only handles write accesses for now
    libvmi_event->reg_event.out_access = VMI_REGACCESS_W;
    libvmi_event->reg_event.value = kvmi_event->event.cr.new_value;
    libvmi_event->reg_event.previous = kvmi_event->event.cr.old_value;

    // call user callback
    event_response_t response = call_event_callback(vmi, libvmi_event);

    // reply struct
    struct {
        struct kvmi_vcpu_hdr hdr;
        struct kvmi_event_reply common;
        struct kvmi_event_cr_reply cr;
    } rpl = {0};

    // set reply action
    rpl.hdr.vcpu = kvmi_event->event.common.vcpu;
    rpl.common.event = kvmi_event->event.common.event;
    rpl.common.action = KVMI_EVENT_ACTION_CONTINUE;

    // the reply value will override the existing one
    rpl.cr.new_val = libvmi_event->reg_event.value;

    return process_cb_response(vmi, response, libvmi_event, kvmi_event, &rpl, sizeof(rpl));
}

static status_t
process_msr(vmi_instance_t vmi, struct kvmi_dom_event *kvmi_event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !kvmi_event) {
        errprint("%s: Invalid vmi or kvmi event handles\n", __func__);
        return VMI_FAILURE;
    }
#endif
    dbprint(VMI_DEBUG_KVM, "--Received MSR event on index 0x%"PRIx32"\n", kvmi_event->event.msr.msr);

    // lookup vmi event
    vmi_event_t *libvmi_event = NULL;
    if (g_hash_table_size(vmi->msr_events)) {
        // test for MSR_ANY in msr_events
        libvmi_event = g_hash_table_lookup(vmi->msr_events, GSIZE_TO_POINTER(kvmi_event->event.msr.msr));
    }

    if (!libvmi_event && g_hash_table_size(vmi->reg_events)) {
        // test for MSR_xxx in reg_events
        libvmi_event = g_hash_table_lookup(vmi->reg_events, GSIZE_TO_POINTER(kvmi_event->event.msr.msr));
    }

    if (!libvmi_event) {
        // test for MSR_ALL in reg_events
        libvmi_event = g_hash_table_lookup(vmi->reg_events, GSIZE_TO_POINTER(MSR_ALL));
        if (libvmi_event) // fill msr field
            libvmi_event->reg_event.msr = kvmi_event->event.msr.msr;
    }

#ifdef ENABLE_SAFETY_CHECKS
    if (!libvmi_event) {
        errprint("%s error: no MSR event handler is registered in LibVMI\n", __func__);
        return VMI_FAILURE;
    }
#endif

    // fill libvmi_event struct
    x86_registers_t regs = {0};
    libvmi_event->x86_regs = &regs;
    struct kvm_regs *kvmi_regs = &kvmi_event->event.common.arch.regs;
    struct kvm_sregs *kvmi_sregs = &kvmi_event->event.common.arch.sregs;
    kvmi_regs_to_libvmi(kvmi_regs, kvmi_sregs, libvmi_event->x86_regs);
    libvmi_event->vcpu_id = kvmi_event->event.common.vcpu;

    //      msr_event
    // TODO: only handle write accesses for now
    libvmi_event->reg_event.out_access = VMI_REGACCESS_W;
    libvmi_event->reg_event.value = kvmi_event->event.msr.new_value;
    libvmi_event->reg_event.previous = kvmi_event->event.msr.old_value;

    // call user callback
    event_response_t response = call_event_callback(vmi, libvmi_event);

    // reply struct
    struct {
        struct kvmi_vcpu_hdr hdr;
        struct kvmi_event_reply common;
        struct kvmi_event_msr_reply msr;
    } rpl = {0};

    // set reply action
    rpl.hdr.vcpu = kvmi_event->event.common.vcpu;
    rpl.common.event = kvmi_event->event.common.event;
    rpl.common.action = KVMI_EVENT_ACTION_CONTINUE;

    // the reply value will override the existing one
    rpl.msr.new_val = libvmi_event->reg_event.value;

    return process_cb_response(vmi, response, libvmi_event, kvmi_event, &rpl, sizeof(rpl));
}

static status_t
process_interrupt(vmi_instance_t vmi, struct kvmi_dom_event *kvmi_event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !kvmi_event)
        return VMI_FAILURE;
#endif
    dbprint(VMI_DEBUG_KVM, "--Received interrupt event\n");

    // lookup vmi_event
    vmi_event_t *libvmi_event = g_hash_table_lookup(vmi->interrupt_events, GUINT_TO_POINTER(INT3));
#ifdef ENABLE_SAFETY_CHECKS
    if ( !libvmi_event ) {
        errprint("%s error: no interrupt event handler is registered in LibVMI\n", __func__);
        return VMI_FAILURE;
    }
#endif

    // fill libvmi_event struct
    x86_registers_t regs = {0};
    libvmi_event->x86_regs = &regs;
    struct kvm_regs *kvmi_regs = &kvmi_event->event.common.arch.regs;
    struct kvm_sregs *kvmi_sregs = &kvmi_event->event.common.arch.sregs;
    kvmi_regs_to_libvmi(kvmi_regs, kvmi_sregs, libvmi_event->x86_regs);
    libvmi_event->vcpu_id = kvmi_event->event.common.vcpu;

    // interrupt_event
    libvmi_event->interrupt_event.gfn = kvmi_event->event.breakpoint.gpa >> vmi->page_shift;
    libvmi_event->interrupt_event.offset = kvmi_event->event.common.arch.regs.rip & VMI_BIT_MASK(0,11);
    libvmi_event->interrupt_event.gla = kvmi_event->event.common.arch.regs.rip;
    // default reinject behavior: invalid
    libvmi_event->interrupt_event.reinject = -1;

    // call user callback
    event_response_t response = call_event_callback(vmi, libvmi_event);

    // reply struct
    struct {
        struct kvmi_vcpu_hdr hdr;
        struct kvmi_event_reply common;
    } rpl = {0};

    // set reply action
    rpl.hdr.vcpu = kvmi_event->event.common.vcpu;
    rpl.common.event = kvmi_event->event.common.event;
    // default action is RETRY: KVM will re-enter the guest
    rpl.common.action = KVMI_EVENT_ACTION_RETRY;

    // action CONTINUE: KVM should handle the event as if
    // the introspection tool did nothing (reinject int3)
    if (libvmi_event->interrupt_event.reinject)
        rpl.common.action = KVMI_EVENT_ACTION_CONTINUE;

    return process_cb_response(vmi, response, libvmi_event, kvmi_event, &rpl, sizeof(rpl));
}

static status_t
process_pagefault(vmi_instance_t vmi, struct kvmi_dom_event *kvmi_event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !kvmi_event)
        return VMI_FAILURE;
#endif
    dbprint(VMI_DEBUG_KVM, "--Received pagefault event\n");

    // build out_access
    vmi_mem_access_t out_access = VMI_MEMACCESS_INVALID;
    if (kvmi_event->event.page_fault.access & KVMI_PAGE_ACCESS_R) out_access |= VMI_MEMACCESS_R;
    if (kvmi_event->event.page_fault.access & KVMI_PAGE_ACCESS_W) out_access |= VMI_MEMACCESS_W;
    if (kvmi_event->event.page_fault.access & KVMI_PAGE_ACCESS_X) out_access |= VMI_MEMACCESS_X;

    // reply struct
    struct kvm_event_pf_reply_packet rpl = {0};

    vmi_event_t *libvmi_event;
    addr_t gfn = kvmi_event->event.page_fault.gpa >> vmi->page_shift;
    // lookup vmi_event
    //      standard ?
    if ( g_hash_table_size(vmi->mem_events_on_gfn) ) {
        libvmi_event = g_hash_table_lookup(vmi->mem_events_on_gfn, GSIZE_TO_POINTER(gfn));
        if (libvmi_event && (libvmi_event->mem_event.in_access & out_access)) {
            // fill libvmi_event struct
            x86_registers_t regs = {0};
            libvmi_event->x86_regs = &regs;
            struct kvm_regs *kvmi_regs = &kvmi_event->event.common.arch.regs;
            struct kvm_sregs *kvmi_sregs = &kvmi_event->event.common.arch.sregs;
            kvmi_regs_to_libvmi(kvmi_regs, kvmi_sregs, libvmi_event->x86_regs);
            libvmi_event->vcpu_id = kvmi_event->event.common.vcpu;
            //      mem_event
            libvmi_event->mem_event.gfn = gfn;
            libvmi_event->mem_event.out_access = out_access;
            libvmi_event->mem_event.gla = kvmi_event->event.page_fault.gva;
            libvmi_event->mem_event.offset = kvmi_event->event.page_fault.gpa & VMI_BIT_MASK(0, 11);
            // TODO
            // libvmi_event->mem_event.valid
            // libvmi_event->mem_event.gptw

            // call user callback
            event_response_t response = call_event_callback(vmi, libvmi_event);

            // handle emulation reply requests
            if (VMI_FAILURE == process_cb_response_emulate(vmi, response, libvmi_event, &rpl))
                return VMI_FAILURE;

            // set reply action
            rpl.hdr.vcpu = kvmi_event->event.common.vcpu;
            rpl.common.event = kvmi_event->event.common.event;
            rpl.common.action = KVMI_EVENT_ACTION_CONTINUE;

            return process_cb_response(vmi, response, libvmi_event, kvmi_event, &rpl, sizeof(rpl));
        }
    }
    //  generic ?
    if ( g_hash_table_size(vmi->mem_events_generic) ) {
        GHashTableIter i;
        vmi_mem_access_t *key = NULL;
        bool cb_issued = 0;

        ghashtable_foreach(vmi->mem_events_generic, i, &key, &libvmi_event) {
            if ( GPOINTER_TO_UINT(key) & out_access ) {
                // fill libvmi_event struct
                x86_registers_t regs = {0};
                libvmi_event->x86_regs = &regs;
                struct kvm_regs *kvmi_regs = &kvmi_event->event.common.arch.regs;
                struct kvm_sregs *kvmi_sregs = &kvmi_event->event.common.arch.sregs;
                kvmi_regs_to_libvmi(kvmi_regs, kvmi_sregs, libvmi_event->x86_regs);
                //      mem_event
                libvmi_event->mem_event.gfn = gfn;
                libvmi_event->mem_event.out_access = out_access;
                libvmi_event->mem_event.gla = kvmi_event->event.page_fault.gva;
                libvmi_event->mem_event.offset = kvmi_event->event.page_fault.gpa & VMI_BIT_MASK(0, 11);
                // TODO
                // libvmi_event->mem_event.valid
                // libvmi_event->mem_event.gptw

                // call user callback
                event_response_t response = call_event_callback(vmi, libvmi_event);

                // handle emulation reply requests
                if (VMI_FAILURE == process_cb_response_emulate(vmi, response, libvmi_event, &rpl))
                    return VMI_FAILURE;

                // set reply action
                rpl.hdr.vcpu = kvmi_event->event.common.vcpu;
                rpl.common.event = kvmi_event->event.common.event;
                rpl.common.action = KVMI_EVENT_ACTION_CONTINUE;

                if (VMI_FAILURE ==
                        process_cb_response(vmi, response, libvmi_event, kvmi_event, &rpl, sizeof(rpl)))
                    return VMI_FAILURE;

                cb_issued = 1;
            }
        }
        if ( cb_issued )
            return VMI_SUCCESS;
    }

    errprint("%s: Caught a memory event that had no handler registered in LibVMI @ GFN 0x%" PRIx64 " (0x%" PRIx64 "), access: %u\n",
             __func__, gfn, (addr_t)kvmi_event->event.page_fault.gpa, out_access);
    return VMI_FAILURE;
}

static status_t
process_descriptor(vmi_instance_t vmi, struct kvmi_dom_event *kvmi_event)
{
    vmi_event_t *libvmi_event = vmi->descriptor_access_event;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !kvmi_event || !libvmi_event) {
        errprint("%s: invalid parameters\n", __func__);
        return VMI_FAILURE;
    }
#endif
    dbprint(VMI_DEBUG_KVM, "--Received descriptor event\n");

    // assign VCPU id
    libvmi_event->vcpu_id = kvmi_event->event.common.vcpu;
    // assign regs
    x86_registers_t libvmi_regs = {0};
    libvmi_event->x86_regs = &libvmi_regs;
    struct kvm_regs *regs = &kvmi_event->event.common.arch.regs;
    struct kvm_sregs *sregs = &kvmi_event->event.common.arch.sregs;
    kvmi_regs_to_libvmi(regs, sregs, libvmi_event->x86_regs);
    // event specific fields
    switch (kvmi_event->event.desc.descriptor) {
        case KVMI_DESC_IDTR:
            libvmi_event->descriptor_event.descriptor = VMI_DESCRIPTOR_IDTR;
            break;
        case KVMI_DESC_GDTR:
            libvmi_event->descriptor_event.descriptor = VMI_DESCRIPTOR_GDTR;
            break;
        case KVMI_DESC_LDTR:
            libvmi_event->descriptor_event.descriptor = VMI_DESCRIPTOR_IDTR;
            break;
        case KVMI_DESC_TR:
            libvmi_event->descriptor_event.descriptor = VMI_DESCRIPTOR_TR;
            break;
        default:
            errprint("Unexpected descriptor ID %d\n", kvmi_event->event.desc.descriptor);
            return VMI_FAILURE;
    }
    libvmi_event->descriptor_event.is_write = kvmi_event->event.desc.write;

    // call user callback
    event_response_t response = call_event_callback(vmi, libvmi_event);

    // reply struct
    struct {
        struct kvmi_vcpu_hdr hdr;
        struct kvmi_event_reply common;
    } rpl = {0};

    // set reply
    rpl.hdr.vcpu = kvmi_event->event.common.vcpu;
    rpl.common.event = kvmi_event->event.common.event;
    rpl.common.action = KVMI_EVENT_ACTION_CONTINUE;

    return process_cb_response(vmi, response, libvmi_event, kvmi_event, &rpl, sizeof(rpl));
}

static status_t
process_pause_event(vmi_instance_t vmi, struct kvmi_dom_event *kvmi_event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !kvmi_event)
        return VMI_FAILURE;
#endif

    // this shouldn't happen
    // the pause event should have been poped by kvm_resume_vm
    // report to the user
    errprint("Unexpected PAUSE event while listening. Did you forget to resume the VM ?\n");

    // always fail, so kvm_events_listen can fail too
    return VMI_FAILURE;
}

status_t
process_singlestep(vmi_instance_t vmi, struct kvmi_dom_event *kvmi_event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !kvmi_event)
        return VMI_FAILURE;
#endif
    dbprint(VMI_DEBUG_KVM, "--Received single step event\n");
    event_response_t response = VMI_EVENT_RESPONSE_NONE;
    vmi_event_t *libvmi_event = NULL;

    if (!vmi->shutting_down) {
        // lookup vmi_event
        libvmi_event = g_hash_table_lookup(vmi->ss_events, GUINT_TO_POINTER(kvmi_event->event.common.vcpu));
#ifdef ENABLE_SAFETY_CHECKS
        if ( !libvmi_event ) {
            errprint("%s error: no single step event handler is registered in LibVMI\n", __func__);
            return VMI_FAILURE;
        }
#endif

        // assign VCPU id
        libvmi_event->vcpu_id = kvmi_event->event.common.vcpu;
        // assign regs
        x86_registers_t libvmi_regs = {0};
        libvmi_event->x86_regs = &libvmi_regs;
        struct kvm_regs *regs = &kvmi_event->event.common.arch.regs;
        struct kvm_sregs *sregs = &kvmi_event->event.common.arch.sregs;
        kvmi_regs_to_libvmi(regs, sregs, libvmi_event->x86_regs);

        // TODO ss_event
        // gfn
        // offset
        libvmi_event->ss_event.gla = libvmi_event->x86_regs->rip;

        // call user callback
        response = call_event_callback(vmi, libvmi_event);
    }

    // reply struct
    struct {
        struct kvmi_vcpu_hdr hdr;
        struct kvmi_event_reply common;
    } rpl = {0};

    // set reply action
    rpl.hdr.vcpu = kvmi_event->event.common.vcpu;
    rpl.common.event = kvmi_event->event.common.event;
    rpl.common.action = KVMI_EVENT_ACTION_CONTINUE;

    return process_cb_response(vmi, response, libvmi_event, kvmi_event, &rpl, sizeof(rpl));
}

static status_t
process_cpuid(vmi_instance_t vmi, struct kvmi_dom_event *kvmi_event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !kvmi_event) {
        errprint("%s: Invalid vmi or kvmi event handles\n", __func__);
        return VMI_FAILURE;
    }
#endif
    dbprint(VMI_DEBUG_KVM, "--Received CPUID event\n");

    // lookup vmi event
    vmi_event_t *libvmi_event = vmi->cpuid_event;
#ifdef ENABLE_SAFETY_CHECKS
    if (!libvmi_event) {
        errprint("%s error: no CPUID event handler is registered in LibVMI\n", __func__);
        return VMI_FAILURE;
    }
#endif

    // fill libvmi_event struct
    x86_registers_t regs = {0};
    libvmi_event->x86_regs = &regs;
    struct kvm_regs *kvmi_regs = &kvmi_event->event.common.arch.regs;
    struct kvm_sregs *kvmi_sregs = &kvmi_event->event.common.arch.sregs;
    kvmi_regs_to_libvmi(kvmi_regs, kvmi_sregs, libvmi_event->x86_regs);

    libvmi_event->vcpu_id = kvmi_event->event.common.vcpu;
    libvmi_event->cpuid_event.leaf = kvmi_event->event.cpuid.function;
    libvmi_event->cpuid_event.subleaf = kvmi_event->event.cpuid.index;

    // call user callback
    event_response_t response = call_event_callback(vmi, libvmi_event);

    // reply struct
    struct {
        struct kvmi_vcpu_hdr hdr;
        struct kvmi_event_reply common;
    } rpl = {0};

    // set reply action
    rpl.hdr.vcpu = kvmi_event->event.common.vcpu;
    rpl.common.event = kvmi_event->event.common.event;
    rpl.common.action = KVMI_EVENT_ACTION_CONTINUE;

    return process_cb_response(vmi, response, libvmi_event, kvmi_event, &rpl, sizeof(rpl));
}


/*
 * kvm_events.h API
 */

status_t
kvm_events_init(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data)
{
    (void)init_flags;
    (void)init_data;

    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm) {
        errprint("%s: Invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    // bind driver functions
    vmi->driver.events_listen_ptr = &kvm_events_listen;
    vmi->driver.are_events_pending_ptr = &kvm_are_events_pending;
    vmi->driver.set_reg_access_ptr = &kvm_set_reg_access;
    vmi->driver.set_intr_access_ptr = &kvm_set_intr_access;
    vmi->driver.set_mem_access_ptr = &kvm_set_mem_access;
    vmi->driver.set_desc_access_event_ptr = &kvm_set_desc_access_event;
    vmi->driver.start_single_step_ptr = &kvm_start_single_step;
    vmi->driver.stop_single_step_ptr = &kvm_stop_single_step;
    vmi->driver.shutdown_single_step_ptr = &kvm_shutdown_single_step;
    vmi->driver.set_cpuid_event_ptr = &kvm_set_cpuid_event;

    // fill event dispatcher
    kvm->process_event[KVMI_EVENT_CR] = &process_register;
    kvm->process_event[KVMI_EVENT_MSR] = &process_msr;
    kvm->process_event[KVMI_EVENT_BREAKPOINT] = &process_interrupt;
    kvm->process_event[KVMI_EVENT_PF] = &process_pagefault;
    kvm->process_event[KVMI_EVENT_DESCRIPTOR] = &process_descriptor;
    kvm->process_event[KVMI_EVENT_PAUSE_VCPU] = &process_pause_event;
    kvm->process_event[KVMI_EVENT_SINGLESTEP] = &process_singlestep;
    kvm->process_event[KVMI_EVENT_CPUID] = &process_cpuid;

    // enable interception of CR/MSR/PF for all VCPUs by default
    // since this has no performance cost
    // the interception will trigger VM-Exists only when using these functions to specify what to intercept
    //  CR:         kvmi_control_cr()
    //  MSR:        kvmi_control_msr()
    //  PF:         kvmi_set_page_access
    //  singlestep: kvmi_control_singlestep()
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        if (kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_CR, true)) {
            errprint("--Failed to enable CR interception\n");
            goto err_exit;
        }
        if (kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_MSR, true)) {
            errprint("--Failed to enable MSR interception\n");
            goto err_exit;
        }
        if (kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_PF, true)) {
            errprint("--Failed to enable page fault interception\n");
            goto err_exit;
        }

        if (kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_SINGLESTEP, true)) {
            errprint("--Failed to enable singlestep monitoring\n");
            goto err_exit;
        }
    }

    return VMI_SUCCESS;
err_exit:
    // disable CR/MSR/PF/singlestep monitoring
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_CR, false);
        kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_MSR, false);
        kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_PF, false);
        kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_SINGLESTEP, false);
    }
    return VMI_FAILURE;
}

void
kvm_events_destroy(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm) {
        errprint("%s: Invalid kvm handle, cleanup is incomplete !\n", __func__);
        return;
    }
#endif
    dbprint(VMI_DEBUG_KVM, "--Destroying KVM driver events\n");
    // pause VM
    dbprint(VMI_DEBUG_KVM, "--Ensure VM is paused\n");
    if (VMI_FAILURE == vmi_pause_vm(vmi))
        errprint("--Failed to pause VM while destroying events\n");

    reg_event_t regevent = { .in_access = VMI_REGACCESS_N };
    if (kvm->monitor_cr0_on) {
        // disable CR0
        regevent.reg = CR0;
        kvm_set_reg_access(vmi, &regevent);
    }

    if (kvm->monitor_cr3_on) {
        // disable CR3
        regevent.reg = CR3;
        kvm_set_reg_access(vmi, &regevent);
    }

    if (kvm->monitor_cr4_on) {
        // disable CR4
        regevent.reg = CR4;
        kvm_set_reg_access(vmi, &regevent);
    }

    if (kvm->monitor_msr_all_on) {
        // disable MSR_ALL
        regevent.reg = MSR_ALL;
        kvm_set_reg_access(vmi, &regevent);
    }

    if (kvm->monitor_intr_on) {
        // disable INT3
        interrupt_event_t intrevent = { .intr = INT3 };
        kvm_set_intr_access(vmi, &intrevent, false);
    }

    if (kvm->monitor_desc_on) {
        // disable descriptor
        kvm_set_desc_access_event(vmi, false);
    }

    if (VMI_FAILURE == kvm_shutdown_single_step(vmi))
        errprint("--Failed to shutdown singlestep\n");

    // disable CR/MSR/PF/singlestep interception
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        if (kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_CR, false))
            errprint("--Failed to disable CR interception\n");
        if (kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_MSR, false))
            errprint("--Failed to disable MSR interception\n");
        if (kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_PF, false))
            errprint("--Failed to disable PF interception\n");
        if (kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_SINGLESTEP, false))
            errprint("--Failed to disable singlestep monitoring\n");
    }

    // clean event queue
    if (kvm_are_events_pending(vmi)) {
        dbprint(VMI_DEBUG_KVM, "--Cleanup event queue\n");
        if (VMI_FAILURE == vmi_events_listen(vmi, 0))
            errprint("--Failed to clean event queue\n");
    }

    // resume VM
    dbprint(VMI_DEBUG_KVM, "--Resume VM\n");
    if (VMI_FAILURE == vmi_resume_vm(vmi))
        errprint("--Failed to resume VM while destroying events\n");
}

static status_t
process_single_event(vmi_instance_t vmi, struct kvmi_dom_event **event)
{
    status_t status = VMI_SUCCESS;
    unsigned int ev_reason = 0;
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    // handle event
    ev_reason = (*event)->event.common.event;

    // special case to handle PAUSE events
    // since they have to managed by vmi_resume_vm(), we simply store them
    // in the kvm_instance for later use by this function
    if (KVMI_EVENT_PAUSE_VCPU == ev_reason) {
#ifdef ENABLE_SAFETY_CHECKS
        uint16_t vcpu = (*event)->event.common.vcpu;
        // silence unused variable warnings if not asserts
        (void) vcpu;
        assert(vcpu < vmi->num_vcpus);
#endif
        dbprint(VMI_DEBUG_KVM, "--Moving PAUSE_VPCU event in the buffer\n");
        kvm->pause_events_list[(*event)->event.common.vcpu] = (*event);
        (*event) = NULL;
        return VMI_SUCCESS;
    }
#ifdef ENABLE_SAFETY_CHECKS
    if (ev_reason >= KVMI_NUM_EVENTS || !kvm->process_event[ev_reason]) {
        errprint("Undefined handler for %u event reason\n", ev_reason);
        status = VMI_FAILURE;
        goto cleanup;
    }
#endif
    if (!vmi->shutting_down) {
        // call handler
        if (VMI_FAILURE == kvm->process_event[ev_reason](vmi, (*event))) {
            status = VMI_FAILURE;
            goto cleanup;
        }
    }

cleanup:
    free((*event));
    (*event) = NULL;
    return status;
}

static status_t
process_pending_events(vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    struct kvmi_dom_event *event = NULL;

    while (kvm->libkvmi.kvmi_get_pending_events(kvm->kvmi_dom) > 0) {
        if (kvm->libkvmi.kvmi_pop_event(kvm->kvmi_dom, &event)) {
            errprint("%s: kvmi_pop_event failed: %s\n", __func__, strerror(errno));
            return VMI_FAILURE;
        }

        process_single_event(vmi, &event);
    }

    return VMI_SUCCESS;
}

static status_t
process_events_with_timeout(vmi_instance_t vmi, uint32_t timeout)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    struct kvmi_dom_event *event = NULL;

    if (kvm_get_next_event(kvm, &event, (kvmi_timeout_t) timeout) == VMI_FAILURE) {
        errprint("%s: Failed to get next KVMi event: %s\n", __func__, strerror(errno));
        return VMI_FAILURE;
    }
    if (!event) {
        return VMI_SUCCESS;
    }

    process_single_event(vmi, &event);

    // make sure that all pending events are processed
    return process_pending_events(vmi);
}

status_t
kvm_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return VMI_FAILURE;

    kvm_instance_t *kvm = kvm_get_instance(vmi);
    if (!kvm || !kvm->kvmi_dom)
        return VMI_FAILURE;

    // kvmi_wait_event() takes a signed integer
    if (timeout > INT_MAX)
        return VMI_FAILURE;
#endif

    GSList *loop;

    if (process_events_with_timeout(vmi, timeout) == VMI_FAILURE) {
        return VMI_FAILURE;
    }

    /*
     * The only way to gracefully handle vmi_swap_events and vmi_clear_event requests
     * that were issued in a callback is to ensure no more kvmi_dom_events
     * are pending. We do this by pausing the domain (all vCPUs)
     * and processing all remaining events. Once no more kvmi_dom_events
     * are pending we can remove/swap the events.
     */
    if (vmi->swap_events || (vmi->clear_events && g_hash_table_size(vmi->clear_events))) {
        vmi_pause_vm(vmi);
        if (process_pending_events(vmi) == VMI_FAILURE) {
            return VMI_FAILURE;
        }

        loop = vmi->swap_events;
        while (loop) {
            swap_wrapper_t *swap_wrapper = loop->data;
            swap_events(vmi, swap_wrapper->swap_from, swap_wrapper->swap_to,
                        swap_wrapper->free_routine);
            g_slice_free(swap_wrapper_t, swap_wrapper);
            loop = loop->next;
        }

        g_slist_free(vmi->swap_events);
        vmi->swap_events = NULL;

        g_hash_table_foreach_remove(vmi->clear_events, clear_events_full, vmi);

        vmi_resume_vm(vmi);
    }

    return VMI_SUCCESS;
}

int
kvm_are_events_pending(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("Invalid VMI handle\n");
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("Invalid kvm or kvmi_dom handles\n");
        return VMI_FAILURE;
    }
#endif
    return kvm->libkvmi.kvmi_get_pending_events(kvm->kvmi_dom);
}

status_t
kvm_set_reg_access(
    vmi_instance_t vmi,
    reg_event_t* event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !event)
        return VMI_FAILURE;
#endif
    int event_id = 0;
    unsigned int kvmi_reg = 0;
    bool enabled = false;

    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom)
        return VMI_FAILURE;
#endif

    // check reg
    switch (event->reg) {
        case CR0:
            event_id = KVMI_EVENT_CR;
            kvmi_reg = 0;
            break;
        case CR3:
            event_id = KVMI_EVENT_CR;
            kvmi_reg = 3;
            break;
        case CR4:
            event_id = KVMI_EVENT_CR;
            kvmi_reg = 4;
            break;
        case MSR_ALL:
            event_id = KVMI_EVENT_MSR;
            break;
        case MSR_ANY:
            event_id = KVMI_EVENT_MSR;
            kvmi_reg = event->msr;
            break;
        case MSR_FLAGS ... MSR_TSC_AUX:
        case MSR_STAR ... MSR_HYPERVISOR:
            errprint("%s error: use MSR_ANY type for specific MSR event registration\n", __FUNCTION__);
            return VMI_FAILURE;
        default:
            errprint("%s: unhandled register %" PRIu64"\n", __func__, event->reg);
            return VMI_FAILURE;
    }

    // check access type
    switch (event->in_access) {
        case VMI_REGACCESS_N:
            enabled = false;
            break;
        case VMI_REGACCESS_W:
            enabled = true;
            break;
        case VMI_REGACCESS_R:
        case VMI_REGACCESS_RW:
            errprint("Register read events are unavailable in KVM.\n");
            return VMI_FAILURE;
        default:
            errprint("Unknown register access mode: %d\n", event->in_access);
            return VMI_FAILURE;
    }

    // handle MSR_ALL here instead of the switch before
    if (event->reg != MSR_ALL) {
        // enable event monitoring for all vcpus
        for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
            if (KVMI_EVENT_CR == event_id)
                if (kvm->libkvmi.kvmi_control_cr(kvm->kvmi_dom, vcpu, kvmi_reg, enabled)) {
                    errprint("%s: kvmi_control_cr failed: %s\n", __func__, strerror(errno));
                    goto error_exit;
                }
            if (KVMI_EVENT_MSR == event_id)
                if (kvm->libkvmi.kvmi_control_msr(kvm->kvmi_dom, vcpu, kvmi_reg, enabled)) {
                    errprint("%s: failed to set MSR event for %s: %s\n", __func__,
                             msr_to_str[kvmi_reg], strerror(errno));
                    goto error_exit;
                }
        }
        // monitoring has been enabled
        char *cr_reg_str = NULL;
        switch (event->reg) {
            case CR0:
                kvm->monitor_cr0_on = enabled;
                cr_reg_str = "CR0";
                break;
            case CR3:
                kvm->monitor_cr3_on = enabled;
                cr_reg_str = "CR3";
                break;
            case CR4:
                kvm->monitor_cr4_on = enabled;
                cr_reg_str = "CR4";
                break;
            default:
                errprint("--Unexpected value for reg: %" PRIu64 "\n", event->reg);
                goto error_exit;
        }
        // silence unused variable if debug disabled
        (void)cr_reg_str;
        dbprint(VMI_DEBUG_KVM, "--%s monitoring on register %s\n",
                (enabled ? "Enabling" : "Disabling"),
                cr_reg_str);
    } else {
        // MSR_ALL
        for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
            for (size_t msr_i=0; msr_i<msr_all_len; msr_i++) {
                kvmi_reg = msr_index[msr_all[msr_i]];
                if (kvm->libkvmi.kvmi_control_msr(kvm->kvmi_dom, vcpu, kvmi_reg, enabled)) {
                    errprint("%s: failed to set MSR event for %s: %s\n", __func__,
                             msr_to_str[msr_all[msr_i]], strerror(errno));
                    continue;
                }
            }
        }
        kvm->monitor_msr_all_on = enabled;
        dbprint(VMI_DEBUG_KVM, "--%s monitoring on all MSRs\n",
                (enabled ? "Enabling" : "Disabling"));
    }

    return VMI_SUCCESS;
error_exit:
    // disable monitoring
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        if (KVMI_EVENT_CR == event_id)
            kvm->libkvmi.kvmi_control_cr(kvm->kvmi_dom, vcpu, kvmi_reg, false);
        if (KVMI_EVENT_MSR == event_id)
            kvm->libkvmi.kvmi_control_msr(kvm->kvmi_dom, vcpu, kvmi_reg, false);
    }
    return VMI_FAILURE;
}

status_t
kvm_set_intr_access(
    vmi_instance_t vmi,
    interrupt_event_t* event,
    bool enabled)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !event)
        return VMI_FAILURE;
#endif

    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom)
        return VMI_FAILURE;
    if (kvm->monitor_intr_on == enabled)
        return VMI_FAILURE;
#endif

    switch (event->intr) {
        case INT3:
            for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++)
                if (kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_BREAKPOINT, enabled)) {
                    errprint("%s: failed to set event on VCPU %u: %s\n", __func__, vcpu, strerror(errno));
                    goto error_exit;
                }
            kvm->monitor_intr_on = enabled;
            break;
        default:
            errprint("KVM driver does not support enabling events for interrupt: %"PRIu32"\n", event->intr);
            return VMI_FAILURE;
    }

    dbprint(VMI_DEBUG_KVM, "--%s interrupt %"PRIu32" monitoring\n",
            (enabled) ? "Enabled" : "Disabled", event->intr);

    return VMI_SUCCESS;
error_exit:
    // disable monitoring for all vcpus
    for (unsigned int i = 0; i < vmi->num_vcpus; i++)
        kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, i, KVMI_EVENT_BREAKPOINT, false);
    kvm->monitor_intr_on = false;
    return VMI_FAILURE;
}

status_t
kvm_set_mem_access(
    vmi_instance_t vmi,
    addr_t gpfn,
    vmi_mem_access_t page_access_flag,
    uint16_t vmm_pagetable_id)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    unsigned char kvmi_access = KVMI_PAGE_ACCESS_R | KVMI_PAGE_ACCESS_W | KVMI_PAGE_ACCESS_X;
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    // sanity check access type
    if (VMI_FAILURE == intel_mem_access_sanity_check(page_access_flag))
        return VMI_FAILURE;

    // check access type and convert to KVMI
    switch (page_access_flag) {
        case VMI_MEMACCESS_N:
            kvmi_access = KVMI_PAGE_ACCESS_R | KVMI_PAGE_ACCESS_W | KVMI_PAGE_ACCESS_X;
            break;
        case VMI_MEMACCESS_R:
            kvmi_access = kvmi_access & ~KVMI_PAGE_ACCESS_R;
            break;
        case VMI_MEMACCESS_W:
            kvmi_access = kvmi_access & ~KVMI_PAGE_ACCESS_W;
            break;
        case VMI_MEMACCESS_X:
            kvmi_access = kvmi_access & ~KVMI_PAGE_ACCESS_X;
            break;
        case VMI_MEMACCESS_RW:
            kvmi_access = kvmi_access & ~(KVMI_PAGE_ACCESS_R | KVMI_PAGE_ACCESS_W);
            break;
        case VMI_MEMACCESS_WX:
            kvmi_access = kvmi_access & ~(KVMI_PAGE_ACCESS_W | KVMI_PAGE_ACCESS_X);
            break;
        case VMI_MEMACCESS_RWX:
            kvmi_access = 0;
            break;
        default:
            errprint("%s: invalid memaccess setting requested\n", __func__);
            return VMI_FAILURE;
    }

    dbprint(VMI_DEBUG_KVM, "--%s: setting page access to %c%c%c on GPFN 0x%" PRIx64 "\n", __func__,
            (kvmi_access & KVMI_PAGE_ACCESS_R) ? 'R' : '_',
            (kvmi_access & KVMI_PAGE_ACCESS_W) ? 'W' : '_',
            (kvmi_access & KVMI_PAGE_ACCESS_X) ? 'X' : '_',
            gpfn);

    // set page access
    long long unsigned int gpa = gpfn << vmi->page_shift;
    if (kvm->libkvmi.kvmi_set_page_access(kvm->kvmi_dom, &gpa, &kvmi_access, 1, vmm_pagetable_id)) {
        errprint("%s: unable to set page access on GPFN 0x%" PRIx64 ": %s\n",
                 __func__, gpfn, strerror(errno));
        return VMI_FAILURE;
    }

    char str_access[4] = {'_', '_', '_', '\0'};
    if (kvmi_access & KVMI_PAGE_ACCESS_R) str_access[0] = 'R';
    if (kvmi_access & KVMI_PAGE_ACCESS_W) str_access[1] = 'W';
    if (kvmi_access & KVMI_PAGE_ACCESS_X) str_access[2] = 'X';

    // silence unused variable if debug disabled
    (void)str_access;
    dbprint(VMI_DEBUG_KVM, "--Setting memaccess permissions to %s on GPFN: 0x%" PRIx64 "\n", str_access, gpfn);
    return VMI_SUCCESS;
}

status_t kvm_set_desc_access_event(
    vmi_instance_t vmi,
    bool enabled)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        if (kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_DESCRIPTOR, enabled)) {
            errprint("%s: kvmi_control_events failed: %s\n", __func__, strerror(errno));
            goto error_exit;
        }
    }

    dbprint(VMI_DEBUG_KVM, "--%s descriptor monitoring\n", (enabled) ? "Enabled" : "Disabled");
    kvm->monitor_desc_on = enabled;

    return VMI_SUCCESS;
error_exit:
    // disable monitoring
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_DESCRIPTOR, false);
    }
    return VMI_FAILURE;
}

status_t
kvm_start_single_step(
    vmi_instance_t vmi,
    single_step_event_t *event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
    if (!event) {
        errprint("%s: invalid event handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
    if ( !event->vcpus ) {
        errprint("%s: --no VCPUs selected for singlestepping\n", __func__);
        return VMI_FAILURE;
    }
#endif

    if ( event->vcpus && event->enable ) {
        for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
            if ( CHECK_VCPU_SINGLESTEP(*event, vcpu) ) {
                if (VMI_FAILURE == kvm_start_single_step_vcpu(vmi, vcpu)) {
                    goto rewind;
                }
            }
        }
    }

    return VMI_SUCCESS;
rewind:
    // disable singlestep
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++)
        if ( CHECK_VCPU_SINGLESTEP(*event, vcpu) )
            kvm_stop_single_step(vmi, vcpu);
    return VMI_FAILURE;
}

status_t
kvm_stop_single_step(
    vmi_instance_t vmi,
    uint32_t vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    dbprint(VMI_DEBUG_KVM, "--Disable MTF flag on vcpu %" PRIu32 "\n", vcpu);

    if (kvm->libkvmi.kvmi_control_singlestep(kvm->kvmi_dom, vcpu, false)) {
        errprint("%s: kvmi_control_singlestep failed: %s\n", __func__, strerror(errno));
        return VMI_FAILURE;
    }

    kvm->sstep_enabled[vcpu] = false;

    return VMI_SUCCESS;
}

status_t
kvm_shutdown_single_step(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    dbprint(VMI_DEBUG_KVM, "--Shutting down single step\n");
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++)
        if (kvm_stop_single_step(vmi, vcpu))
            return VMI_FAILURE;

    // disabling singlestep monitoring is done at driver destroy
    return VMI_SUCCESS;
}

status_t
kvm_set_cpuid_event(vmi_instance_t vmi, bool enabled)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return VMI_FAILURE;
#endif

    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom)
        return VMI_FAILURE;
#endif

    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++)
        if (kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_CPUID, enabled)) {
            errprint("%s: failed to set event on VCPU %u: %s\n", __func__, vcpu, strerror(errno));
            goto error_exit;
        }

    dbprint(VMI_DEBUG_KVM, "--%s CPUID monitoring\n",
            (enabled) ? "Enabled" : "Disabled");

    return VMI_SUCCESS;
error_exit:
    // disable monitoring for all vcpus
    for (unsigned int i = 0; i < vmi->num_vcpus; i++)
        kvm->libkvmi.kvmi_control_events(kvm->kvmi_dom, i, KVMI_EVENT_CPUID, false);
    return VMI_FAILURE;
}

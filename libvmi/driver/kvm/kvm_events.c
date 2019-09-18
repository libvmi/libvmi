/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
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

#include "private.h"
#include "msr-index.h"
#include "kvm_events.h"
#include "kvm_private.h"
#include "include/kvmi/libkvmi.h"

/*
 * Helpers
 */
static void
fill_ev_common_kvmi_to_libvmi(
        struct kvmi_dom_event *kvmi_event,
        vmi_event_t *libvmi_event)
{
    //      standard regs
    libvmi_event->x86_regs->rax = kvmi_event->event.common.arch.regs.rax;
    libvmi_event->x86_regs->rbx = kvmi_event->event.common.arch.regs.rbx;
    libvmi_event->x86_regs->rcx = kvmi_event->event.common.arch.regs.rcx;
    libvmi_event->x86_regs->rdx = kvmi_event->event.common.arch.regs.rdx;
    libvmi_event->x86_regs->rsi = kvmi_event->event.common.arch.regs.rsi;
    libvmi_event->x86_regs->rdi = kvmi_event->event.common.arch.regs.rdi;
    libvmi_event->x86_regs->rip = kvmi_event->event.common.arch.regs.rip;
    libvmi_event->x86_regs->rsp = kvmi_event->event.common.arch.regs.rsp;
    libvmi_event->x86_regs->rbp = kvmi_event->event.common.arch.regs.rbp;
    libvmi_event->x86_regs->rflags = kvmi_event->event.common.arch.regs.rflags;
    libvmi_event->x86_regs->r8 = kvmi_event->event.common.arch.regs.r8;
    libvmi_event->x86_regs->r9 = kvmi_event->event.common.arch.regs.r9;
    libvmi_event->x86_regs->r10 = kvmi_event->event.common.arch.regs.r10;
    libvmi_event->x86_regs->r11 = kvmi_event->event.common.arch.regs.r11;
    libvmi_event->x86_regs->r12 = kvmi_event->event.common.arch.regs.r12;
    libvmi_event->x86_regs->r13 = kvmi_event->event.common.arch.regs.r13;
    libvmi_event->x86_regs->r14 = kvmi_event->event.common.arch.regs.r14;
    libvmi_event->x86_regs->r15 = kvmi_event->event.common.arch.regs.r15;
    //      special regs
    //          Control Registers
    libvmi_event->x86_regs->cr0 = kvmi_event->event.common.arch.sregs.cr0;
    libvmi_event->x86_regs->cr2 = kvmi_event->event.common.arch.sregs.cr2;
    libvmi_event->x86_regs->cr3 = kvmi_event->event.common.arch.sregs.cr3;
    libvmi_event->x86_regs->cr4 = kvmi_event->event.common.arch.sregs.cr4;
    //          CS
    libvmi_event->x86_regs->cs_base = kvmi_event->event.common.arch.sregs.cs.base;
    libvmi_event->x86_regs->cs_limit = kvmi_event->event.common.arch.sregs.cs.limit;
    libvmi_event->x86_regs->cs_sel = kvmi_event->event.common.arch.sregs.cs.selector;
    //          DS
    libvmi_event->x86_regs->ds_base = kvmi_event->event.common.arch.sregs.ds.base;
    libvmi_event->x86_regs->ds_limit = kvmi_event->event.common.arch.sregs.ds.limit;
    libvmi_event->x86_regs->ds_sel = kvmi_event->event.common.arch.sregs.ds.selector;
    //          SS
    libvmi_event->x86_regs->ss_base = kvmi_event->event.common.arch.sregs.ss.base;
    libvmi_event->x86_regs->ss_limit = kvmi_event->event.common.arch.sregs.ss.limit;
    libvmi_event->x86_regs->ss_sel = kvmi_event->event.common.arch.sregs.ss.selector;
    //          ES
    libvmi_event->x86_regs->es_base = kvmi_event->event.common.arch.sregs.es.base;
    libvmi_event->x86_regs->es_limit = kvmi_event->event.common.arch.sregs.es.limit;
    libvmi_event->x86_regs->es_sel = kvmi_event->event.common.arch.sregs.es.selector;
    //          FS
    libvmi_event->x86_regs->fs_base = kvmi_event->event.common.arch.sregs.fs.base;
    libvmi_event->x86_regs->fs_limit = kvmi_event->event.common.arch.sregs.fs.limit;
    libvmi_event->x86_regs->fs_sel = kvmi_event->event.common.arch.sregs.fs.selector;
    //          GS
    libvmi_event->x86_regs->gs_base = kvmi_event->event.common.arch.sregs.gs.base;
    libvmi_event->x86_regs->gs_limit = kvmi_event->event.common.arch.sregs.gs.limit;
    libvmi_event->x86_regs->gs_sel = kvmi_event->event.common.arch.sregs.gs.selector;
    //      VCPU
    libvmi_event->vcpu_id = kvmi_event->event.common.vcpu;
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
    if (!libvmi_event || !kvmi_event || !rpl) {
        errprint("%s: invalid libvmi/kvmi/rpl handles\n", __func__);
        return VMI_FAILURE;
    }
#endif
    // loop over all possible responses
    for (uint32_t i = VMI_EVENT_RESPONSE_NONE+1; i <=__VMI_EVENT_RESPONSE_MAX; i++) {
        event_response_t candidate = 1u << i;
        if (response & candidate) {
            switch (candidate) {
                default:
                    errprint("%s: KVM - unhandled event reponse %u\n", __func__, candidate);
                    break;
            }
        }
    }
    // the rpl struct should be like this
    //    struct {
    //        struct kvmi_vcpu_hdr hdr;
    //        struct kvmi_event_reply common;
    //        // Event specific structs
    //        ...
    //    };
    struct kvmi_vcpu_hdr *hdr = (struct kvmi_vcpu_hdr *)rpl;
    hdr->vcpu = kvmi_event->event.common.vcpu;

    struct kvmi_event_reply *common = (struct kvmi_event_reply *)( hdr + 1 );
    common->event = kvmi_event->event.common.event;
    common->action = KVMI_EVENT_ACTION_CONTINUE;

    if (kvmi_reply_event(kvm->kvmi_dom, kvmi_event->seq, rpl, rpl_size))
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
process_register(vmi_instance_t vmi, struct kvmi_dom_event *event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !event)
        return VMI_FAILURE;
#endif
    dbprint(VMI_DEBUG_KVM, "--Received CR event\n");
    return VMI_SUCCESS;
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
        gint key = kvmi_event->event.msr.msr;
        libvmi_event = g_hash_table_lookup(vmi->msr_events, &key);
    }

    if (!libvmi_event && g_hash_table_size(vmi->reg_events)) {
        // test for MSR_xxx in reg_events
        gint key = kvmi_event->event.msr.msr;
        libvmi_event = g_hash_table_lookup(vmi->reg_events, &key);
    }

    if (!libvmi_event) {
        // test for MSR_ALL in reg_events
        gint key = MSR_ALL;
        libvmi_event = g_hash_table_lookup(vmi->reg_events, &key);
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
    fill_ev_common_kvmi_to_libvmi(kvmi_event, libvmi_event);

    //      msr_event
    libvmi_event->reg_event.value = kvmi_event->event.msr.new_value;
    libvmi_event->reg_event.previous = kvmi_event->event.msr.old_value;
    // TODO
    // libvmi_event->reg_event.out_access

    // call user callback
    event_response_t response = call_event_callback(vmi, libvmi_event);

    // reply struct
    struct {
        struct kvmi_vcpu_hdr hdr;
        struct kvmi_event_reply common;
        struct kvmi_event_msr_reply msr;
    } rpl = {0};

    // TODO: how can the callback specifiy a new value for the MSR ?
    // libvmi_event.reg_event.xxx

    // the reply new value will be used anyway,
    // write the new val from the kvmi event
    rpl.msr.new_val = kvmi_event->event.msr.new_value;
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
    gint key = INT3;
    vmi_event_t *libvmi_event = g_hash_table_lookup(vmi->interrupt_events, &key);
#ifdef ENABLE_SAFETY_CHECKS
    if ( !libvmi_event ) {
        errprint("%s error: no interrupt event handler is registered in LibVMI\n", __func__);
        return VMI_FAILURE;
    }
#endif

    // fill libvmi_event struct
    x86_registers_t regs = {0};
    libvmi_event->x86_regs = &regs;
    fill_ev_common_kvmi_to_libvmi(kvmi_event, libvmi_event);

    //      interrupt_event
    // TODO: hardcoded PAGE_SHIFT
    libvmi_event->interrupt_event.gfn = kvmi_event->event.breakpoint.gpa >> vmi->page_shift;
    // TODO: vector and type
    // event->interrupt_event.vector =
    // event->interrupt_event.type =
    libvmi_event->interrupt_event.cr2 = kvmi_event->event.common.arch.sregs.cr2;
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

    vmi_event_t *libvmi_event;
    addr_t gfn = kvmi_event->event.page_fault.gpa >> vmi->page_shift;
    // lookup vmi_event
    //      standard ?
    if ( g_hash_table_size(vmi->mem_events_on_gfn) ) {
        // TODO: hardcoded page shift

        libvmi_event = g_hash_table_lookup(vmi->mem_events_on_gfn, &gfn);
        if (libvmi_event && (libvmi_event->mem_event.in_access & out_access)) {
            // fill libvmi_event struct
            x86_registers_t regs = {0};
            libvmi_event->x86_regs = &regs;
            fill_ev_common_kvmi_to_libvmi(kvmi_event, libvmi_event);
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

            // reply struct
            struct {
                struct kvmi_vcpu_hdr hdr;
                struct kvmi_event_reply common;
                struct kvmi_event_pf_reply pf;
            } rpl = {0};

            return process_cb_response(vmi, response, libvmi_event, kvmi_event, &rpl, sizeof(rpl));
        }
    }
    //  generic ?
    if ( g_hash_table_size(vmi->mem_events_generic) ) {
        GHashTableIter i;
        vmi_mem_access_t *key = NULL;
        bool cb_issued = 0;

        ghashtable_foreach(vmi->mem_events_generic, i, &key, &libvmi_event) {
            if ( (*key) & out_access ) {
                // fill libvmi_event struct
                x86_registers_t regs = {0};
                libvmi_event->x86_regs = &regs;
                fill_ev_common_kvmi_to_libvmi(kvmi_event, libvmi_event);
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

                // struct reply
                struct {
                    struct kvmi_vcpu_hdr hdr;
                    struct kvmi_event_reply common;
                    struct kvmi_event_pf_reply pf;
                } rpl = {0};

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
    vmi->driver.set_reg_access_ptr = &kvm_set_reg_access;
    vmi->driver.set_intr_access_ptr = &kvm_set_intr_access;
    vmi->driver.set_mem_access_ptr = &kvm_set_mem_access;

    // fill event dispatcher
    kvm->process_event[KVMI_EVENT_CR] = &process_register;
    kvm->process_event[KVMI_EVENT_MSR] = &process_msr;
    kvm->process_event[KVMI_EVENT_BREAKPOINT] = &process_interrupt;
    kvm->process_event[KVMI_EVENT_PF] = &process_pagefault;
    kvm->process_event[KVMI_EVENT_PAUSE_VCPU] = &process_pause_event;

    // enable monitoring of CR and MSR for all VCPUs by default
    // since this has no performance cost
    // the interception is activated only when specific registers
    // have been defined via kvmi_control_cr(), kvmi_control_msr()
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        if (kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_CR, true)) {
            errprint("--Failed to enable CR monitoring\n");
            goto err_exit;
        }
        if (kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_MSR, true)) {
            errprint("--Failed to enable MSR monitoring\n");
            goto err_exit;
        }
    }

    return VMI_SUCCESS;
err_exit:
    // disable CR/MSR monitoring
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_CR, false);
        kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_MSR, false);
    }
    return VMI_FAILURE;
}

void
kvm_events_destroy(
        vmi_instance_t vmi)
{
    (void)vmi;

    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm) {
        errprint("%s: Invalid kvm handle, cleanup is incomplete !\n", __func__);
        return;
    }
#endif
    // disable CR/MSR monitoring
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        if (kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_CR, false))
            errprint("--Failed to disable CR monitoring\n");
        if (kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_MSR, false))
            errprint("--Failed to disable MSR monitoring\n");
    }
}

status_t
kvm_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return VMI_FAILURE;
#endif
    struct kvmi_dom_event *event = NULL;
    unsigned int ev_reason = 0;

    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom)
        return VMI_FAILURE;
#endif

    // wait next event
    if (kvmi_wait_event(kvm->kvmi_dom, (kvmi_timeout_t)timeout)) {
        if (errno == ETIMEDOUT) {
            // no events !
            return VMI_SUCCESS;
        }
        errprint("%s: kvmi_wait_event failed: %s\n", __func__, strerror(errno));
        return VMI_FAILURE;
    }

    // pop event from queue
    if (kvmi_pop_event(kvm->kvmi_dom, &event)) {
        errprint("%s: kvmi_pop_event failed: %s\n", __func__, strerror(errno));
        return VMI_FAILURE;
    }

    // handle event
    ev_reason = event->event.common.event;
#ifdef ENABLE_SAFETY_CHECKS
    if ( ev_reason >= KVMI_NUM_EVENTS || !kvm->process_event[ev_reason] ) {
        errprint("Undefined handler for %u event reason\n", ev_reason);
        return VMI_FAILURE;
    }
#endif
    // call handler
    if (VMI_FAILURE == kvm->process_event[ev_reason](vmi, event))
        goto error_exit;

    return VMI_SUCCESS;
error_exit:
    if (event)
        free(event);
    return VMI_FAILURE;
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
                if (kvmi_control_cr(kvm->kvmi_dom, vcpu, kvmi_reg, enabled)) {
                    errprint("%s: kvmi_control_cr failed: %s\n", __func__, strerror(errno));
                    goto error_exit;
                }
            if (KVMI_EVENT_MSR == event_id)
                if (kvmi_control_msr(kvm->kvmi_dom, vcpu, kvmi_reg, enabled)) {
                    errprint("%s: failed to set MSR event for %s: %s\n", __func__,
                             msr_to_str[kvmi_reg], strerror(errno));
                    goto error_exit;
                }
        }
        dbprint(VMI_DEBUG_KVM, "--Done %s monitoring on register %" PRIu64"\n",
                (enabled ? "enabling" : "disabling"),
                event->reg);
    } else {
        // MSR_ALL
        for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
            for (size_t msr_i=0; msr_i<msr_all_len; msr_i++) {
                kvmi_reg = msr_index[msr_all[msr_i]];
                if (kvmi_control_msr(kvm->kvmi_dom, vcpu, kvmi_reg, enabled)) {
                    // this call fails on MSR_HYPERVISOR
                    // to avoid breaking MSR_ALL feature, we simply continue
                    // and print an error message
                    errprint("%s: failed to set MSR event for %s: %s\n", __func__,
                             msr_to_str[msr_all[msr_i]], strerror(errno));
                    continue;
                }
            }
        }
        dbprint(VMI_DEBUG_KVM, "--Set MSR events on all MSRs\n");
    }

    return VMI_SUCCESS;
error_exit:
    // disable monitoring
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        if (KVMI_EVENT_CR == event_id)
            kvmi_control_cr(kvm->kvmi_dom, vcpu, kvmi_reg, false);
        if (KVMI_EVENT_MSR == event_id)
            kvmi_control_msr(kvm->kvmi_dom, vcpu, kvmi_reg, false);
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
#endif

    switch (event->intr) {
        case INT3:
            for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++)
                if (kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_BREAKPOINT, enabled)) {
                    errprint("%s: failed to set event on VCPU %u: %s\n", __func__, vcpu, strerror(errno));
                    goto error_exit;
                }
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
        kvmi_control_events(kvm->kvmi_dom, i, KVMI_EVENT_BREAKPOINT, false);
    return VMI_FAILURE;
}

status_t
kvm_set_mem_access(
        vmi_instance_t vmi,
        addr_t gpfn,
        vmi_mem_access_t page_access_flag,
        uint16_t UNUSED(vmm_pagetable_id))
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    static bool pf_enabled = false;
    unsigned char kvmi_access, kvmi_orig_access;
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    // enable PF events the first time we call this function
    // this avoids enabling them at kvm_init_vmi, since we don't
    // know if the app is going to use mem_events at all
    // TODO: move this at driver init ?
    if (!pf_enabled) {
        bool pf_enabled_succeeded = true;
        for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
            if (kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_PF, true)) {
                pf_enabled_succeeded = false;
                errprint("%s: Fail to enable PF events on VCPU %u: %s\n", __func__, vcpu, strerror(errno));
                break;
            }
        }
        if (!pf_enabled_succeeded) {
            // disable PF for all vcpu and fail
            for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++)
                kvmi_control_events(kvm->kvmi_dom, vcpu, KVMI_EVENT_PF, false);
            return VMI_FAILURE;
        }
        pf_enabled = true;
    }

    // get previous access type
    if (kvmi_get_page_access(kvm->kvmi_dom, gpfn, &kvmi_orig_access)) {
        errprint("%s: kvmi_get_page_access failed: %s\n", __func__, strerror(errno));
        return VMI_FAILURE;
    }

    // check access type and convert to KVMI
    switch (page_access_flag) {
        case VMI_MEMACCESS_N:
            kvmi_access = 0;
            break;
        case VMI_MEMACCESS_R:
            kvmi_access = kvmi_orig_access & ~KVMI_PAGE_ACCESS_R;
            break;
        case VMI_MEMACCESS_W:
            kvmi_access = kvmi_orig_access & ~KVMI_PAGE_ACCESS_W;
            break;
        case VMI_MEMACCESS_X:
            kvmi_access = kvmi_orig_access & ~KVMI_PAGE_ACCESS_X;
            break;
        case VMI_MEMACCESS_RW:
            kvmi_access = kvmi_orig_access & ~(KVMI_PAGE_ACCESS_R | KVMI_PAGE_ACCESS_W);
            break;
        case VMI_MEMACCESS_WX:
            kvmi_access = kvmi_orig_access & ~(KVMI_PAGE_ACCESS_W | KVMI_PAGE_ACCESS_X);
            break;
        case VMI_MEMACCESS_RWX:
            kvmi_access = 0;
            break;
        default:
            errprint("%s: invalid memaccess setting requested\n", __func__);
            return VMI_FAILURE;
    }

    // set page access
    long long unsigned int gpa = gpfn << vmi->page_shift;
    if (kvmi_set_page_access(kvm->kvmi_dom, &gpa, &kvmi_access, vmi->num_vcpus)) {
        errprint("%s: unable to set page access on GPFN 0x%" PRIx64 ": %s\n",
                 __func__, gpfn, strerror(errno));
        return VMI_FAILURE;
    }

    dbprint(VMI_DEBUG_KVM, "--Done setting memaccess on GPFN: 0x%" PRIx64 "\n", gpfn);
    return VMI_SUCCESS;
}

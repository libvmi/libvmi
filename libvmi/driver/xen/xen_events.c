/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
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
#include <string.h>

#include "private.h"
#include "driver/driver_wrapper.h"
#include "driver/xen/xen.h"
#include "driver/xen/xen_private.h"
#include "driver/xen/xen_events.h"
#include "driver/xen/xen_events_private.h"
#include "driver/xen/msr-index.h"

/*
 * Event control functions
 */
status_t xen_set_mem_access(vmi_instance_t vmi, addr_t gpfn,
                            vmi_mem_access_t page_access_flag, uint16_t altp2m_idx)
{
    int rc;
    xenmem_access_t access;
    xen_instance_t *xen = xen_get_instance(vmi);
    xc_interface * xch = xen_get_xchandle(vmi);
    domid_t dom = xen_get_domainid(vmi);

#ifdef ENABLE_SAFETY_CHECKS
    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( dom == (domid_t)VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    if ( VMI_FAILURE == convert_vmi_flags_to_xenmem(page_access_flag, &access) )
        return VMI_FAILURE;

    if ( !altp2m_idx )
        rc = xen->libxcw.xc_set_mem_access(xch, dom, access, gpfn, 1); // 1 page at a time
    else
        rc = xen->libxcw.xc_altp2m_set_mem_access(xch, dom, altp2m_idx, gpfn, access);

    if (rc) {
        errprint("xc_hvm_set_mem_access failed with code: %d\n", rc);
        return VMI_FAILURE;
    }
    dbprint(VMI_DEBUG_XEN, "--Done Setting memaccess on GPFN: %"PRIu64"\n", gpfn);
    return VMI_SUCCESS;
}

status_t xen_set_reg_access(vmi_instance_t vmi, reg_event_t *event)
{
    bool enable;
    int rc;
    xc_interface * xch = xen_get_xchandle(vmi);
    domid_t dom = xen_get_domainid(vmi);
    xen_events_t * xe = xen_get_events(vmi);
    xen_instance_t * xen = xen_get_instance(vmi);
    bool sync = !event->async;

#ifdef ENABLE_SAFETY_CHECKS
    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        goto done;
    }

    if ( dom == (domid_t)VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        goto done;
    }
#endif

    switch ( event->reg ) {
        case CR0:
        case CR3:
        case CR4:
        case XCR0:
            if ( !(xe->monitor_capabilities & (1u << XEN_DOMCTL_MONITOR_EVENT_WRITE_CTRLREG)) ) {
                errprint("%s error: no system support for event type\n", __FUNCTION__);
                goto done;
            }
            break;

        case MSR_ANY: /* fall-through */
        case MSR_ALL:
            if ( !(xe->monitor_capabilities & (1u << XEN_DOMCTL_MONITOR_EVENT_MOV_TO_MSR)) ) {
                errprint("%s error: no system support for event type\n", __FUNCTION__);
                goto done;
            }
            break;
        case MSR_FLAGS ... MSR_TSC_AUX:
        case MSR_STAR ... MSR_HYPERVISOR:
            errprint("%s error: use MSR_ANY type for specific MSR event registration\n", __FUNCTION__);
            goto done;
        default:
            errprint("%s error: no system support for event type\n", __FUNCTION__);
            goto done;
    }

    switch ( event->in_access ) {
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

    switch ( event->reg ) {
        case CR0:
            if ( enable == xe->monitor_cr0_on )
                goto done;

            rc = xen->libxcw.xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR0,
                    enable, sync, event->onchange);
            if ( rc )
                goto done;

            xe->monitor_cr0_on = enable;
            break;
        case CR3:
            if ( enable == xe->monitor_cr3_on )
                goto done;

            rc = xen->libxcw.xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR3,
                    enable, sync, event->onchange);
            if ( rc )
                goto done;

            xe->monitor_cr3_on = enable;
            break;
        case CR4:
            if ( enable == xe->monitor_cr4_on )
                goto done;

            rc = xen->libxcw.xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR4,
                    enable, sync, event->onchange);
            if ( rc )
                goto done;

            xe->monitor_cr4_on = enable;
            break;
        case XCR0:
            if ( enable == xe->monitor_xcr0_on )
                goto done;

            rc = xen->libxcw.xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_XCR0,
                    enable, sync, event->onchange);
            if ( rc )
                goto done;

            xe->monitor_xcr0_on = enable;
            break;
        case MSR_ALL:
            if ( enable == xe->monitor_msr_on )
                goto done;

            size_t i;
            for (i=0; i<sizeof(msr_all)/sizeof(reg_t); i++) {
                dbprint(VMI_DEBUG_XEN, "--Setting monitor MSR: %"PRIx32" to %i\n", msr_index[msr_all[i]], enable);
                if ( xen->libxcw.xc_monitor_mov_to_msr2(xch, dom, msr_index[msr_all[i]], enable) )
                    dbprint(VMI_DEBUG_XEN, "--Setting monitor MSR: %"PRIx32" FAILED\n", msr_index[msr_all[i]]);
            }

            xe->monitor_msr_on = enable;
            break;
        case MSR_ANY:
            if ( !event->msr )
                goto done;

            if ( xen->libxcw.xc_monitor_mov_to_msr2(xch, dom, event->msr, enable) ) {
                dbprint(VMI_DEBUG_XEN, "--Setting monitor MSR: %"PRIx32" FAILED\n", event->msr);
                goto done;
            }
            break;
        default:
            errprint("Tried to register for unsupported register event.\n");
            goto done;
    }

    return VMI_SUCCESS;

done:
    return VMI_FAILURE;
}

status_t xen_set_int3_access(vmi_instance_t vmi, bool enable)
{
    xc_interface * xch = xen_get_xchandle(vmi);
    domid_t dom = xen_get_domainid(vmi);
    xen_events_t *xe = xen_get_events(vmi);
    xen_instance_t *xen = xen_get_instance(vmi);

#ifdef ENABLE_SAFETY_CHECKS
    if ( !xen ) {
        errprint("%s error: invalid xen_instance_t handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( dom == (domid_t)VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( enable == xe->monitor_intr_on )
        return VMI_FAILURE;
#endif

    if ( !(xe->monitor_capabilities & (1u << XEN_DOMCTL_MONITOR_EVENT_SOFTWARE_BREAKPOINT)) ) {
        errprint("%s error: no system support for event type\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( xen->libxcw.xc_monitor_software_breakpoint(xch, dom, enable) )
        return VMI_FAILURE;

    xe->monitor_intr_on = enable;
    return VMI_SUCCESS;
}

status_t xen_set_intr_access(vmi_instance_t vmi, interrupt_event_t *event, bool enabled)
{
    switch ( event->intr ) {
        case INT3:
            return xen_set_int3_access(vmi, enabled);
        case INT_NEXT:
            return VMI_SUCCESS;
        default:
            errprint("Xen driver does not support enabling events for interrupt: %"PRIu32"\n", event->intr);
            break;
    }

    return VMI_FAILURE;
}

status_t xen_stop_single_step(vmi_instance_t vmi, uint32_t vcpu)
{
    xen_instance_t *xen = xen_get_instance(vmi);

    int rc = xen->libxcw.xc_domain_debug_control(xen->xchandle,
             xen->domainid,
             XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF,
             vcpu);

    if ( !rc )
        dbprint(VMI_DEBUG_XEN, "--Removing MTF flag from vcpu %u\n", vcpu);

    return rc ? VMI_FAILURE : VMI_SUCCESS;
}

status_t xen_start_single_step(vmi_instance_t vmi, single_step_event_t *event)
{
    domid_t dom = xen_get_domainid(vmi);
    xen_events_t *xe = xen_get_events(vmi);
    xen_instance_t *xen = xen_get_instance(vmi);
    int rc;
    uint32_t i;

    if ( !(xe->monitor_capabilities & (1u << XEN_DOMCTL_MONITOR_EVENT_SINGLESTEP)) ) {
        errprint("%s error: no system support for event type\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    dbprint(VMI_DEBUG_XEN, "--Starting single step on domain %"PRIu16"\n", dom);

    if ( !xe->monitor_singlestep_on ) {
        rc = xen->libxcw.xc_monitor_singlestep(xen_get_xchandle(vmi), dom, true);
        if ( rc<0 ) {
            errprint("Error %d setting HVM single step\n", rc);
            return VMI_FAILURE;
        }

        xe->monitor_singlestep_on = 1;
    }

    /*
     * We only actually flip the MTF flag if the 'enable' option is specified.
     * This is necessariy if singlestep is used by flipping on the event_response_t option
     * as LibVMI needs to be able to catch and forward those events.
     */
    if ( event->vcpus && event->enable ) {
        for (i=0 ; i < MAX_SINGLESTEP_VCPUS; i++) {
            if ( CHECK_VCPU_SINGLESTEP(*event, i) ) {
                dbprint(VMI_DEBUG_XEN, "--Setting MTF flag on vcpu %u\n", i);

                rc = xen->libxcw.xc_domain_debug_control(xen->xchandle,
                        xen->domainid,
                        XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON,
                        i);

                if ( rc < 0 ) {
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

status_t xen_shutdown_single_step(vmi_instance_t vmi)
{
    domid_t dom = xen_get_domainid(vmi);
    xen_events_t *xe = xen_get_events(vmi);
    xen_instance_t *xen = xen_get_instance(vmi);
    int rc = -1;
    uint32_t i=0;

    dbprint(VMI_DEBUG_XEN, "--Shutting down single step on domain %"PRIu16"\n", dom);

    for (; i<vmi->num_vcpus; i++) {
        xen_stop_single_step(vmi, i);
    }

    if ( xe->monitor_singlestep_on ) {
        rc = xen->libxcw.xc_monitor_singlestep(xen_get_xchandle(vmi), dom,false);

        if (rc<0) {
            errprint("Error %d disabling single step\n", rc);
            return VMI_FAILURE;
        }

        xe->monitor_singlestep_on = 0;
    }

    return VMI_SUCCESS;
}

status_t xen_set_guest_requested_event(vmi_instance_t vmi, bool enabled)
{
    int rc;
    xen_instance_t *xen = xen_get_instance(vmi);

    if ( xen->major_version != 4 || xen->minor_version < 8 )
        return VMI_FAILURE;

    if ( !enabled && !vmi->guest_requested_event )
        return VMI_SUCCESS;

    rc  = xen->libxcw.xc_monitor_guest_request(xen_get_xchandle(vmi),
            xen_get_domainid(vmi),
            enabled, 1);
    if ( rc < 0 ) {
        errprint("Error %i setting guest request monitor\n", rc);
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t xen_set_debug_event(vmi_instance_t vmi, bool enabled)
{
    int rc;
    xen_instance_t *xen = xen_get_instance(vmi);

    if ( xen->major_version != 4 || xen->minor_version < 8 )
        return VMI_FAILURE;

    if ( !enabled && !vmi->debug_event )
        return VMI_SUCCESS;

    rc = xen->libxcw.xc_monitor_debug_exceptions(xen_get_xchandle(vmi),
            xen_get_domainid(vmi),
            enabled, 1);

    if ( rc < 0 ) {
        errprint("Error %i setting debug event monitor\n", rc);
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}


status_t xen_set_cpuid_event(vmi_instance_t vmi, bool enabled)
{
    int rc;
    xen_instance_t *xen = xen_get_instance(vmi);

    if ( xen->major_version != 4 || xen->minor_version < 8 )
        return VMI_FAILURE;

    if ( !enabled && !vmi->cpuid_event )
        return VMI_SUCCESS;

    rc = xen->libxcw.xc_monitor_cpuid(xen_get_xchandle(vmi),
                                      xen_get_domainid(vmi),
                                      enabled);
    if ( rc < 0 ) {
        errprint("Error %i setting CPUID event monitor\n", rc);
        return VMI_FAILURE;
    }

    if ( !enabled )
        vmi->cpuid_event = NULL;

    return VMI_SUCCESS;
}


status_t xen_set_privcall_event(vmi_instance_t vmi, bool enabled)
{
    int rc;
    xc_interface * xch = xen_get_xchandle(vmi);
    domid_t dom = xen_get_domainid(vmi);
    xen_events_t *xe = xen_get_events(vmi);
    xen_instance_t *xen = xen_get_instance(vmi);

#ifdef ENABLE_SAFETY_CHECKS
    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( dom == (domid_t)VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    if ( xen->major_version != 4 || xen->minor_version < 8 )
        return VMI_FAILURE;

    if ( !(xe->monitor_capabilities & (1u << XEN_DOMCTL_MONITOR_EVENT_PRIVILEGED_CALL)) ) {
        errprint("%s error: no system support for event type\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( !enabled && !vmi->privcall_event ) {
        return VMI_FAILURE;
    }

    rc = xen->libxcw.xc_monitor_privileged_call(xch, dom, enabled);
    if ( rc < 0 ) {
        errprint("Error %i setting privcall event monitor\n", rc);
        return VMI_FAILURE;
    }

    if ( !enabled )
        vmi->privcall_event = NULL;

    return VMI_SUCCESS;
}

status_t xen_set_desc_access_event(vmi_instance_t vmi, bool enabled)
{
    int rc;
    xen_instance_t *xen = xen_get_instance(vmi);

    if ( xen->major_version != 4 || xen->minor_version < 10 )
        return VMI_FAILURE;

    if ( !enabled && !vmi->descriptor_access_event )
        return VMI_SUCCESS;

    rc = xen->libxcw.xc_monitor_descriptor_access(xen_get_xchandle(vmi),
            xen_get_domainid(vmi),
            enabled);

    if ( rc < 0 ) {
        errprint("Error %i setting descriptor access event monitor\n", rc);
        return VMI_FAILURE;
    }

    if ( !enabled )
        vmi->descriptor_access_event = NULL;

    return VMI_SUCCESS;
}

status_t xen_set_failed_emulation_event(vmi_instance_t vmi, bool enabled)
{
    int rc;
    xen_instance_t *xen = xen_get_instance(vmi);

    if ( xen->major_version != 4 || xen->minor_version < 11 )
        return VMI_FAILURE;

    if ( !enabled && !vmi->failed_emulation_event )
        return VMI_SUCCESS;

    rc = xen->libxcw.xc_monitor_emul_unimplemented(xen_get_xchandle(vmi),
            xen_get_domainid(vmi),
            enabled);

    if ( rc < 0 ) {
        errprint("Error %i setting failed emulation event monitor\n", rc);
        return VMI_FAILURE;
    }

    if ( !enabled )
        vmi->failed_emulation_event = NULL;

    return VMI_SUCCESS;
}


/*
 * Event processing functions
 */

/*
 * Here we check for response flags placed on the event in the callback
 * that allows triggering Xen vm_event response flags.
 */
static
void process_response ( event_response_t response, vmi_event_t *event, vm_event_compat_t *rsp )
{
    if ( response && event ) {
        uint32_t i = VMI_EVENT_RESPONSE_NONE+1;

        for (; i<=__VMI_EVENT_RESPONSE_MAX; i++) {
            event_response_t er = 1u << i;

            if ( response & er ) {
                switch ( er ) {
                    case VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID:
                        rsp->altp2m_idx = event->slat_id;
                        break;
                    case VMI_EVENT_RESPONSE_EMULATE_NOWRITE:
                        rsp->flags |= event_response_conversion[VMI_EVENT_RESPONSE_EMULATE];
                        break;
                    case VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA:
                        if ( event->emul_read ) {
                            rsp->flags |= event_response_conversion[VMI_EVENT_RESPONSE_EMULATE];

                            if ( event->emul_read->size < sizeof(rsp->data.emul.read.data) )
                                rsp->data.emul.read.size = event->emul_read->size;
                            else
                                rsp->data.emul.read.size = sizeof(rsp->data.emul.read.data);

                            memcpy(&rsp->data.emul.read.data,
                                   &event->emul_read->data,
                                   rsp->data.emul.read.size);

                            if ( !event->emul_read->dont_free )
                                free(event->emul_read);
                        }
                        break;
                    case VMI_EVENT_RESPONSE_SET_EMUL_INSN:
                        if ( event->emul_insn ) {
                            rsp->flags |= event_response_conversion[VMI_EVENT_RESPONSE_EMULATE];

                            memcpy(&rsp->data.emul.insn.data,
                                   &event->emul_insn->data,
                                   sizeof(rsp->data.emul.insn.data));

                            if ( !event->emul_insn->dont_free )
                                free(event->emul_insn);
                        }
                        break;
                    case VMI_EVENT_RESPONSE_SET_REGISTERS:
#if defined(I386) || defined(X86_64)
                        memcpy(&rsp->data.regs.x86, event->x86_regs, sizeof(struct regs_x86));
#elif defined(ARM32) || defined(ARM64)
                        memcpy(&rsp->data.regs.arm, event->arm_regs, sizeof(struct regs_arm));
#endif
                        break;
                };

                rsp->flags |= event_response_conversion[er];
            }
        }
    }
}

static
status_t process_software_breakpoint(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    gint lookup = INT3;
    xen_instance_t *xen = xen_get_instance(vmi);
    vmi_event_t *event = g_hash_table_lookup(vmi->interrupt_events, &lookup);

    if ( !event )
        return VMI_FAILURE;

    event->interrupt_event.gfn = vmec->software_breakpoint.gfn;
    event->interrupt_event.reinject = -1;
    event->interrupt_event.insn_length = vmec->software_breakpoint.insn_length;
    event->interrupt_event.offset = vmec->data.regs.x86.rip & VMI_BIT_MASK(0,11);
    event->interrupt_event.gla = vmec->data.regs.x86.rip;

    event->x86_regs = (x86_registers_t *)&vmec->data.regs.x86;
    event->slat_id = vmec->altp2m_idx;
    event->vcpu_id = vmec->vcpu_id;

    vmi->event_callback = 1;
    process_response( event->callback(vmi, event), event, vmec );
    vmi->event_callback = 0;

    /* Reinject (callback may decide) */
    if ( !event->interrupt_event.reinject )
        return VMI_SUCCESS;

    if ( -1 == event->interrupt_event.reinject ) {
        errprint("%s Need to specify reinjection behaviour!\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    dbprint(VMI_DEBUG_XEN, "rip %"PRIx64" gfn %"PRIx64"\n",
            event->interrupt_event.gla, event->interrupt_event.gfn);

    /*
     *  Undocumented enough to be worth describing at length:
     *  If enabled, INT3 events are reported via the vm_event
     *  facilities of Xen only for the 1-byte 0xCC variant of the
     *  instruction. The 2-byte 0xCD imm8 variant taking the
     *  interrupt vector as an operand (i.e., 0xCD03) is NOT
     *  reported in the same fashion (These details are valid as of
     *  Xen 4.11).
     *
     *  In order for INT3 to be handled correctly by the VM
     *  kernel and subsequently passed on to the debugger within a
     *  VM, the trap must be re-injected. Because only 0xCC is in
     *  play for events, the instruction length involved is
     *  _normally_ only one byte. However, the instruction may have
     *  arbitrary prefixes attached that change the instruction's length.
     *  Since prefixes have no effect on int3 no legitimate compiler/debugger
     *  adds any, but a malicious guest could to probe for inaccurate event
     *  reinjection.
     */
    int rc = xen->libxcw.xc_hvm_inject_trap(xen_get_xchandle(vmi),
                                            xen_get_domainid(vmi),
                                            vmec->vcpu_id,
                                            X86_TRAP_INT3,     /* Vector 3 for INT3 */
                                            X86_TRAP_sw_exc,   /* Trap type, here a software intr */
                                            ~0u, /* error code. ~0u means 'ignore' */
                                            event->interrupt_event.insn_length,
                                            0    /* cr2 need not be preserved */
                                           );

    if (rc < 0) {
        errprint("%s : Xen event error %d re-injecting software breakpoint\n", __FUNCTION__, rc);
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

static
status_t process_interrupt(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    gint lookup = INT_NEXT;
    vmi_event_t *event = g_hash_table_lookup(vmi->interrupt_events, &lookup);

#ifdef ENABLE_SAFETY_CHECKS
    if ( !event ) {
        errprint("%s error: no interrupt event handler is registered in LibVMI\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    if ( VMI_SUCCESS == vmi_pagetable_lookup(vmi, vmec->data.regs.x86.cr3, vmec->data.regs.x86.rip, &event->interrupt_event.gfn) )
        event->interrupt_event.gfn >>= 12;
    else
        event->interrupt_event.gfn = ~0ull;

    event->interrupt_event.vector = vmec->x86_interrupt.vector;
    event->interrupt_event.type = vmec->x86_interrupt.type;
    event->interrupt_event.cr2 = vmec->x86_interrupt.cr2;
    event->interrupt_event.offset = vmec->data.regs.x86.rip & VMI_BIT_MASK(0,11);
    event->interrupt_event.gla = vmec->data.regs.x86.rip;

    event->x86_regs = (x86_registers_t *)&vmec->data.regs.x86;
    event->slat_id = vmec->altp2m_idx;
    event->vcpu_id = vmec->vcpu_id;

    vmi->event_callback = 1;
    process_response( event->callback(vmi, event), event, vmec );
    vmi->event_callback = 0;

    return VMI_SUCCESS;
}

static
status_t process_register(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    reg_t convert[] = {
        [VM_EVENT_X86_CR0] = CR0,
        [VM_EVENT_X86_CR3] = CR3,
        [VM_EVENT_X86_CR4] = CR4,
        [VM_EVENT_X86_XCR0] = XCR0
    };

    gint lookup = convert[vmec->write_ctrlreg.index];
    vmi_event_t * event = g_hash_table_lookup(vmi->reg_events, &lookup);

    switch ( lookup ) {
        case MSR_ALL: {
            /* Check if it's a MSR_ANY event */
            lookup = vmec->mov_to_msr.msr;
            if ( !event && !(event = g_hash_table_lookup(vmi->msr_events, &lookup)) )
                return VMI_FAILURE;

            event->reg_event.msr = vmec->mov_to_msr.msr;
            event->reg_event.value = vmec->mov_to_msr.new_value;
            event->reg_event.previous = vmec->mov_to_msr.old_value;
            break;
        }
        case CR0:
        case CR3:
        case CR4:
        case XCR0:
#ifdef ENABLE_SAFETY_CHECKS
            if ( !event )
                return VMI_FAILURE;
#endif
            /*
             * event->reg_event.equal allows for setting a reg event for
             *  a specific VALUE of the register
             */
            if ( event->reg_event.equal && event->reg_event.equal != vmec->write_ctrlreg.new_value )
                return VMI_SUCCESS;

            event->reg_event.value = vmec->write_ctrlreg.new_value;
            event->reg_event.previous = vmec->write_ctrlreg.old_value;
            break;
        default:
            break;
    }

    event->x86_regs = (x86_registers_t *)&vmec->data.regs.x86;
    event->slat_id = vmec->altp2m_idx;
    event->vcpu_id = vmec->vcpu_id;

    vmi->event_callback = 1;
    process_response ( event->callback(vmi, event), event, vmec );
    vmi->event_callback = 0;

    return VMI_SUCCESS;
}

static
status_t process_singlestep(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    gint lookup = vmec->vcpu_id;
    vmi_event_t * event = g_hash_table_lookup(vmi->ss_events, &lookup);

#ifdef ENABLE_SAFETY_CHECKS
    if ( !event ) {
        errprint("%s error: no singlestep handler is registered in LibVMI\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    event->ss_event.gfn = vmec->singlestep.gfn;
    event->ss_event.offset = vmec->data.regs.x86.rip & VMI_BIT_MASK(0,11);
    event->ss_event.gla = vmec->data.regs.x86.rip;

    event->x86_regs = (x86_registers_t *)&vmec->data.regs.x86;
    event->slat_id = vmec->altp2m_idx;
    event->vcpu_id = vmec->vcpu_id;

    vmi->event_callback = 1;
    process_response ( event->callback(vmi, event), event, vmec );
    vmi->event_callback = 0;

    return VMI_SUCCESS;
}

static inline
event_response_t issue_mem_cb(vmi_instance_t vmi,
                              vmi_event_t *event,
                              vm_event_compat_t *vmec,
                              vmi_mem_access_t out_access)
{
    if ( vmec->mem_access.flags & MEM_ACCESS_GLA_VALID ) {
        event->mem_event.gptw = !!(vmec->mem_access.flags & MEM_ACCESS_FAULT_IN_GPT);
        event->mem_event.gla_valid = 1;
        event->mem_event.gla = vmec->mem_access.gla;
    } else
        event->mem_event.gla = 0ull;

    event->mem_event.gfn = vmec->mem_access.gfn;
    event->mem_event.offset = vmec->mem_access.offset;
    event->mem_event.out_access = out_access;
    event->vcpu_id = vmec->vcpu_id;

    return event->callback(vmi, event);
}

static
status_t process_mem(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    vmi_event_t *event;
    vmi_mem_access_t out_access = VMI_MEMACCESS_INVALID;

    if (vmec->mem_access.flags & MEM_ACCESS_R) out_access |= VMI_MEMACCESS_R;
    if (vmec->mem_access.flags & MEM_ACCESS_W) out_access |= VMI_MEMACCESS_W;
    if (vmec->mem_access.flags & MEM_ACCESS_X) out_access |= VMI_MEMACCESS_X;

    if ( g_hash_table_size(vmi->mem_events_on_gfn) ) {
        event = g_hash_table_lookup(vmi->mem_events_on_gfn, &vmec->mem_access.gfn);

        if (event && (event->mem_event.in_access & out_access) ) {
            event->x86_regs = (x86_registers_t *)&vmec->data.regs.x86;
            event->slat_id = vmec->altp2m_idx;

            vmi->event_callback = 1;
            process_response( issue_mem_cb(vmi, event, vmec, out_access), event, vmec );
            vmi->event_callback = 0;

            return VMI_SUCCESS;
        }
    }

    if ( g_hash_table_size(vmi->mem_events_generic) ) {
        GHashTableIter i;
        vmi_mem_access_t *key = NULL;
        bool cb_issued = 0;

        ghashtable_foreach(vmi->mem_events_generic, i, &key, &event) {
            if ( (*key) & out_access ) {
                event->x86_regs = (x86_registers_t *)&vmec->data.regs.x86;
                event->slat_id = vmec->altp2m_idx;

                vmi->event_callback = 1;
                process_response( issue_mem_cb(vmi, event, vmec, out_access), event, vmec );
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
    errprint("Caught a memory event that had no handler registered in LibVMI @ GFN 0x%" PRIx64 " (0x%" PRIx64 "), access: %u\n",
             vmec->mem_access.gfn, (vmec->mem_access.gfn<<12) + vmec->mem_access.offset, out_access);
    return VMI_FAILURE;
}

static
status_t process_debug_exception(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    vmi_event_t * event = vmi->debug_event;

#ifdef ENABLE_SAFETY_CHECKS
    if ( !event ) {
        errprint("%s error: no debug event handler is registered in LibVMI\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    event->debug_event.reinject = -1;
    event->debug_event.gla = vmec->data.regs.x86.rip;
    event->debug_event.offset = vmec->data.regs.x86.rip & VMI_BIT_MASK(0,11);
    event->debug_event.gfn = vmec->debug_exception.gfn;
    event->debug_event.type = vmec->debug_exception.type;
    event->debug_event.insn_length = vmec->debug_exception.insn_length;

    event->x86_regs = (x86_registers_t *)&vmec->data.regs.x86;
    event->slat_id = vmec->altp2m_idx;
    event->vcpu_id = vmec->vcpu_id;

    vmi->event_callback = 1;
    process_response ( event->callback(vmi, event),
                       event, vmec );
    vmi->event_callback = 0;

    if ( -1 == event->debug_event.reinject ) {
        errprint("%s Need to specify reinjection behaviour!\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if ( !event->debug_event.reinject )
        return VMI_SUCCESS;

    xen_instance_t *xen = xen_get_instance(vmi);
    int rc = xen->libxcw.xc_hvm_inject_trap(xen_get_xchandle(vmi),
                                            xen_get_domainid(vmi),
                                            vmec->vcpu_id,
                                            X86_TRAP_DEBUG,
                                            vmec->debug_exception.type, -1,
                                            vmec->debug_exception.insn_length,
                                            vmec->data.regs.x86.cr2);
    if (rc < 0) {
        errprint("%s error %d injecting debug exception\n", __FUNCTION__, rc);
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

static
status_t process_cpuid(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    vmi_event_t * event = vmi->cpuid_event;

#ifdef ENABLE_SAFETY_CHECKS
    if ( !event ) {
        errprint("%s error: no CPUID event handler is registered in LibVMI\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    event->cpuid_event.insn_length = vmec->cpuid.insn_length;
    event->cpuid_event.leaf = vmec->cpuid.leaf;
    event->cpuid_event.subleaf = vmec->cpuid.subleaf;

    event->x86_regs = (x86_registers_t *)&vmec->data.regs.x86;
    event->slat_id = vmec->altp2m_idx;
    event->vcpu_id = vmec->vcpu_id;

    vmi->event_callback = 1;
    process_response ( event->callback(vmi, event),
                       event, vmec );
    vmi->event_callback = 0;

    if ( !vmec->flags || vmec->flags == (1 << VM_EVENT_FLAG_VCPU_PAUSED) )
        dbprint(VMI_DEBUG_XEN, "%s warning: CPUID events require the callback to specify how to handle it, we are likely to be going into a CPUID loop right now\n",
                __FUNCTION__);

    return VMI_SUCCESS;
}

static
status_t process_privcall(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    vmi_event_t * event = vmi->privcall_event;

#ifdef ENABLE_SAFETY_CHECKS
    if ( !event ) {
        errprint("%s error: no privileged call event handler is registered in LibVMI\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    event->privcall_event.offset = vmec->data.regs.arm.pc & VMI_BIT_MASK(0,11);
    event->privcall_event.gla = vmec->data.regs.arm.pc;

    if ( VMI_FAILURE == vmi_translate_kv2p(vmi, vmec->data.regs.arm.pc, &event->privcall_event.gfn) ) {
        errprint("%s: cannot translate pc to physical address\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    event->privcall_event.gfn >>= 12;

    event->arm_regs = (arm_registers_t *)&vmec->data.regs.arm;
    event->slat_id = vmec->altp2m_idx;
    event->vcpu_id = vmec->vcpu_id;

    vmi->event_callback = 1;
    process_response ( event->callback(vmi, event),
                       event, vmec );
    vmi->event_callback = 0;

    /*
     * SMC instructions are currently not re-injected. In the future, we might encounter a scenario,
     * in which SMC re-injections become necessary as SMC invocations are possible from inside the guest.
     */

    return VMI_SUCCESS;
}

static
status_t process_guest_request(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    vmi_event_t * event = vmi->guest_requested_event;

#ifdef ENABLE_SAFETY_CHECKS
    if ( !event ) {
        errprint("%s error: no guest requested event handler is registered in LibVMI\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

#if defined(I386) || defined(X86_64)
    event->x86_regs = (x86_registers_t *)&vmec->data.regs.x86;
#elif defined(ARM32) || defined(ARM64)
    event->arm_regs = (arm_registers_t *)&vmec->data.regs.arm;
#endif
    event->slat_id = vmec->altp2m_idx;
    event->vcpu_id = vmec->vcpu_id;

    vmi->event_callback = 1;
    process_response ( event->callback(vmi, event),
                       event, vmec );
    vmi->event_callback = 0;

    return VMI_SUCCESS;
}

static
status_t process_unimplemented_emul(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    vmi_event_t * event = vmi->failed_emulation_event;

#ifdef ENABLE_SAFETY_CHECKS
    if ( !event ) {
        errprint("%s error: no unimplemented emulation event handler is registered in LibVMI\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    event->x86_regs = (x86_registers_t *)&vmec->data.regs.x86;
    event->slat_id = vmec->altp2m_idx;
    event->vcpu_id = vmec->vcpu_id;

    vmi->event_callback = 1;
    process_response ( event->callback(vmi, event),
                       event, vmec );
    vmi->event_callback = 0;

    return VMI_SUCCESS;
}

static
status_t process_desc_access(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    vmi_event_t * event = vmi->descriptor_access_event;

#ifdef ENABLE_SAFETY_CHECKS
    if ( !event ) {
        errprint("%s error: no descriptor access event handler is registered in LibVMI\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    event->descriptor_event.exit_info = vmec->desc_access.arch.svm.exitinfo;
    event->descriptor_event.exit_qualification = vmec->desc_access.arch.vmx.exit_qualification;
    event->descriptor_event.descriptor = vmec->desc_access.descriptor;
    event->descriptor_event.is_write = vmec->desc_access.is_write;

    event->x86_regs = (x86_registers_t *)&vmec->data.regs.x86;
    event->slat_id = vmec->altp2m_idx;
    event->vcpu_id = vmec->vcpu_id;

    vmi->event_callback = 1;
    process_response ( event->callback(vmi, event),
                       event, vmec );
    vmi->event_callback = 0;

    return VMI_SUCCESS;
}

static
status_t process_request(vmi_instance_t vmi, vm_event_compat_t *vmec)
{
    xen_events_t *xe = xen_get_events(vmi);

#ifdef ENABLE_SAFETY_CHECKS
    if ( !xe->process_event[vmec->reason] )
        return VMI_FAILURE;
#endif

    vmec->altp2m_idx = (vmec->flags & VM_EVENT_FLAG_ALTERNATE_P2M) ?: 0;
    return xe->process_event[vmec->reason](vmi, vmec);
}

/*
 * Xen 4.6 ring functions
 */

static inline
void ring_get_request_and_response_46(xen_events_t *xe,
                                      vm_event_46_request_t **req,
                                      vm_event_46_request_t **rsp)
{
    vm_event_46_back_ring_t *back_ring = &xe->back_ring_46;
    RING_IDX req_cons = back_ring->req_cons;
    RING_IDX rsp_prod = back_ring->rsp_prod_pvt;

    *req = RING_GET_REQUEST(back_ring, req_cons);
    *rsp = RING_GET_RESPONSE(back_ring, rsp_prod);

    // Update ring positions
    req_cons++;
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;
    back_ring->rsp_prod_pvt++;
}

static
status_t process_requests_46(vmi_instance_t vmi)
{
    vm_event_46_request_t *req;
    vm_event_46_response_t *rsp;
    vm_event_compat_t vmec;
    xen_events_t *xe = xen_get_events(vmi);
    xen_instance_t *xen = xen_get_instance(vmi);
    status_t vrc = VMI_SUCCESS;

    while ( RING_HAS_UNCONSUMED_REQUESTS(&xe->back_ring_46) ) {

        ring_get_request_and_response_46(xe, &req, &rsp);

        if ( req->version != 0x00000001 ) {
            errprint("Error, Xen reports a VM_EVENT_INTERFACE_VERSION that doesn't match what we expected (0x00000001)!\n");
            return VMI_FAILURE;
        }

        vmec.version = req->version;
        vmec.flags = req->flags;
        vmec.reason = req->reason;
        vmec.vcpu_id = req->vcpu_id;
        vmec.altp2m_idx = req->altp2m_idx;

#if defined(I386) || defined(X86_64)
        memcpy(&vmec.data.regs.x86, &req->data.regs.x86, sizeof(vmec.data.regs.x86));
#endif

        switch ( vmec.reason ) {
            case VM_EVENT_REASON_MEM_ACCESS:
                memcpy(&vmec.mem_access, &req->u.mem_access, sizeof(vmec.mem_access));
                break;

            case VM_EVENT_REASON_WRITE_CTRLREG:
                memcpy(&vmec.write_ctrlreg, &req->u.write_ctrlreg, sizeof(vmec.write_ctrlreg));
                break;

            case VM_EVENT_REASON_MOV_TO_MSR:
                vmec.mov_to_msr.msr = req->u.mov_to_msr.msr;
                vmec.mov_to_msr.new_value = req->u.mov_to_msr.value;
                break;

            case VM_EVENT_REASON_SINGLESTEP:
                memcpy(&vmec.singlestep, &req->u.singlestep, sizeof(vmec.singlestep));
                break;

            case VM_EVENT_REASON_SOFTWARE_BREAKPOINT:
                memcpy(&vmec.software_breakpoint, &req->u.software_breakpoint, sizeof(vmec.software_breakpoint));
                break;
        };

        if ( VMI_FAILURE == process_request(vmi, &vmec) )
            vrc = VMI_FAILURE;

        rsp->version = vmec.version;
        rsp->vcpu_id = vmec.vcpu_id;
        rsp->flags = vmec.flags;
        rsp->reason = vmec.reason;
        rsp->altp2m_idx = vmec.altp2m_idx;

        memcpy(&rsp->data, &vmec.data, sizeof(rsp->data));

        RING_PUSH_RESPONSES(&xe->back_ring_46);

        if (vmi->num_vcpus >= 7 && xen->libxcw.xc_evtchn_notify(xe->xce_handle, xe->port) ) {
            errprint("Error resuming domain.\n");
            return VMI_FAILURE;
        }
    }

    return vrc;
}

int xen_are_events_pending_46(vmi_instance_t vmi)
{
    xen_events_t *xe = xen_get_events(vmi);

#ifdef ENABLE_SAFETY_CHECKS
    if ( !xe ) {
        errprint("%s error: invalid xen_events_t handle\n", __FUNCTION__);
        return -1;
    }
#endif

    return RING_HAS_UNCONSUMED_REQUESTS(&xe->back_ring_46);
}

static
status_t init_events_46(vmi_instance_t vmi)
{
    xen_events_t * xe = xen_get_events(vmi);

    vmi->driver.are_events_pending_ptr = &xen_are_events_pending_46;
    xe->process_requests = &process_requests_46;

    SHARED_RING_INIT((vm_event_46_sring_t *)xe->ring_page);
    BACK_RING_INIT(&xe->back_ring_46,
                   (vm_event_46_sring_t *)xe->ring_page,
                   XC_PAGE_SIZE);

    return VMI_SUCCESS;
}

/*
 * Xen 4.8 ring functions
 */

static inline
void ring_get_request_and_response_48(xen_events_t *xe,
                                      vm_event_48_request_t **req,
                                      vm_event_48_request_t **rsp)
{
    vm_event_48_back_ring_t *back_ring = &xe->back_ring_48;
    RING_IDX req_cons = back_ring->req_cons;
    RING_IDX rsp_prod = back_ring->rsp_prod_pvt;

    *req = RING_GET_REQUEST(back_ring, req_cons);
    *rsp = RING_GET_RESPONSE(back_ring, rsp_prod);

    // Update ring positions
    req_cons++;
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;
    back_ring->rsp_prod_pvt++;
}

status_t process_requests_48(vmi_instance_t vmi)
{
    vm_event_48_request_t *req;
    vm_event_48_response_t *rsp;
    vm_event_compat_t vmec;
    xen_events_t *xe = xen_get_events(vmi);
    xen_instance_t *xen = xen_get_instance(vmi);
    status_t vrc = VMI_SUCCESS;

    while ( RING_HAS_UNCONSUMED_REQUESTS(&xe->back_ring_48) ) {

        ring_get_request_and_response_48(xe, &req, &rsp);

        if ( req->version > 0x00000003 ) {
            errprint("Error, Xen reports a VM_EVENT_INTERFACE_VERSION that is newer then what we understand (0x%x > 0x%x)!\n",
                     req->version, 0x00000003);
            return VMI_FAILURE;
        }

        vmec.version = req->version;
        vmec.flags = req->flags;
        vmec.reason = req->reason;
        vmec.vcpu_id = req->vcpu_id;
        vmec.altp2m_idx = req->altp2m_idx;

#if defined(I386) || defined(X86_64)
        memcpy(&vmec.data.regs.x86, &req->data.regs.x86, sizeof(vmec.data.regs.x86));
#elif defined(ARM32) || defined(ARM64)
        memcpy(&vmec.data.regs.arm, &req->data.regs.arm, sizeof(vmec.data.regs.arm));
#endif

        switch ( vmec.reason ) {
            case VM_EVENT_REASON_MEM_ACCESS:
                memcpy(&vmec.mem_access, &req->u.mem_access, sizeof(vmec.mem_access));
                break;

            case VM_EVENT_REASON_WRITE_CTRLREG:
                memcpy(&vmec.write_ctrlreg, &req->u.write_ctrlreg, sizeof(vmec.write_ctrlreg));
                break;

            case VM_EVENT_REASON_MOV_TO_MSR:
                if ( xen->minor_version < 11 ) {
                    vmec.mov_to_msr.msr = req->u.mov_to_msr_46.msr;
                    vmec.mov_to_msr.new_value = req->u.mov_to_msr_46.value;
                } else
                    memcpy(&vmec.mov_to_msr, &req->u.mov_to_msr_411, sizeof(vmec.mov_to_msr));
                break;

            case VM_EVENT_REASON_SINGLESTEP:
                memcpy(&vmec.singlestep, &req->u.singlestep, sizeof(vmec.singlestep));
                break;

            case VM_EVENT_REASON_SOFTWARE_BREAKPOINT:
                memcpy(&vmec.software_breakpoint, &req->u.software_breakpoint, sizeof(vmec.software_breakpoint));
                break;

            case VM_EVENT_REASON_INTERRUPT:
                memcpy(&vmec.x86_interrupt, &req->u.interrupt.x86, sizeof(vmec.x86_interrupt));
                break;

            case VM_EVENT_REASON_DEBUG_EXCEPTION:
                memcpy(&vmec.debug_exception, &req->u.debug_exception, sizeof(vmec.debug_exception));
                break;

            case VM_EVENT_REASON_CPUID:
                memcpy(&vmec.cpuid, &req->u.cpuid, sizeof(vmec.cpuid));
                break;

            case VM_EVENT_REASON_DESCRIPTOR_ACCESS:
                memcpy(&vmec.desc_access, &req->u.desc_access, sizeof(vmec.desc_access));
                break;
        }

        if ( VMI_FAILURE == process_request(vmi, &vmec) )
            vrc = VMI_FAILURE;

        rsp->version = vmec.version;
        rsp->vcpu_id = vmec.vcpu_id;
        rsp->flags = vmec.flags;
        rsp->reason = vmec.reason;
        rsp->altp2m_idx = vmec.altp2m_idx;

        memcpy(&rsp->data, &vmec.data, sizeof(rsp->data));

        RING_PUSH_RESPONSES(&xe->back_ring_48);

        if (vmi->num_vcpus >= 7 && xen->libxcw.xc_evtchn_notify(xe->xce_handle, xe->port) ) {
            errprint("Error resuming domain.\n");
            return VMI_FAILURE;
        }
    }

    return vrc;
}

int xen_are_events_pending_48(vmi_instance_t vmi)
{
    xen_events_t *xe = xen_get_events(vmi);

#ifdef ENABLE_SAFETY_CHECKS
    if ( !xe ) {
        errprint("%s error: invalid xen_events_t handle\n", __FUNCTION__);
        return -1;
    }
#endif

    return RING_HAS_UNCONSUMED_REQUESTS(&xe->back_ring_48);
}

status_t init_events_48(vmi_instance_t vmi)
{
    xen_events_t *xe = xen_get_events(vmi);

    xe->process_requests = &process_requests_48;
    vmi->driver.are_events_pending_ptr = &xen_are_events_pending_48;

    SHARED_RING_INIT((vm_event_48_sring_t *)xe->ring_page);
    BACK_RING_INIT(&xe->back_ring_48,
                   (vm_event_48_sring_t *)xe->ring_page,
                   XC_PAGE_SIZE);

    return VMI_SUCCESS;
}


/*
 * Main event functions
 */

static
status_t unmask_event(xen_instance_t *xen, xen_events_t *xe)
{
    int rc, port = xen->libxcw.xc_evtchn_pending(xe->xce_handle);

#ifdef ENABLE_SAFETY_CHECKS
    if ( -1 == port ) {
        errprint("Failed to read port from event channel\n");
        return VMI_FAILURE;
    }

    if ( port != xe->port ) {
        errprint("Event received for invalid port %i, Expected port is %i\n",
                 port, xe->port);
        return VMI_FAILURE;
    }
#endif

    rc = xen->libxcw.xc_evtchn_unmask(xe->xce_handle, port);

#ifdef ENABLE_SAFETY_CHECKS
    if ( rc ) {
        errprint("Failed to unmask event channel port\n");
        return VMI_FAILURE;
    }
#endif

    return VMI_SUCCESS;
}

static
status_t wait_for_event_or_timeout(vmi_instance_t vmi, unsigned long ms)
{
    xen_instance_t *xen = xen_get_instance(vmi);
    xen_events_t *xe = xen_get_events(vmi);

    switch ( poll(&xe->fd, 1, ms) ) {
        case -1:
            if (errno == EINTR)
                return VMI_SUCCESS;

            errprint("Poll exited with an error\n");
            return VMI_FAILURE;
        case 0:
            return VMI_SUCCESS;
        default:
            return unmask_event(xen, xe);
    };

    return VMI_FAILURE;
}

status_t xen_events_listen(vmi_instance_t vmi, uint32_t timeout)
{
    xen_events_t *xe = xen_get_events(vmi);
    xen_instance_t *xen = xen_get_instance(vmi);

    int rc = -1;
    status_t vrc = VMI_SUCCESS;

#ifdef ENABLE_SAFETY_CHECKS
    if ( !xen ) {
        errprint("%s error: invalid xen_instance_t handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( !xe ) {
        errprint("%s error: invalid xen_events_t handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    if (!vmi->shutting_down) {
        if ( timeout ) {
            dbprint(VMI_DEBUG_XEN, "--Waiting for xen events...(%"PRIu32" ms)\n", timeout);
            if ( VMI_FAILURE == wait_for_event_or_timeout(vmi, timeout) ) {
                errprint("Error while waiting for event.\n");
                return VMI_FAILURE;
            }
        } else if ( VMI_FAILURE == unmask_event(xen, xe) ) {
            errprint("Error while unmasking event.\n");
            return VMI_FAILURE;
        }
    }

    vrc = xe->process_requests(vmi);

    /*
     * The only way to gracefully handle vmi_swap_events and vmi_clear_event requests
     * that were issued in a callback is to ensure no more requests
     * are in the ringpage. We do this by pausing the domain (all vCPUs)
     * and processing all reamining events on the ring. Once no more requests
     * are on the ring we can remove/swap the events.
     */
    if ( vmi->swap_events || (vmi->clear_events && g_hash_table_size(vmi->clear_events)) ) {
        vmi_pause_vm(vmi);

        vrc = xe->process_requests(vmi);

        GSList *loop = vmi->swap_events;
        while (loop) {
            swap_wrapper_t *swap_wrapper = loop->data;
            swap_events(vmi, swap_wrapper->swap_from, swap_wrapper->swap_to,
                        swap_wrapper->free_routine);
            loop = loop->next;
        }

        g_hash_table_foreach_remove(vmi->clear_events, clear_events_full, vmi);

        vmi_resume_vm(vmi);
    }

    /*
     * Resume the domain once all requests are processed from the ring
     *
     * Note: it is more performant to send notification after each event if
     * there are a lot of vCPUs assigned to the VM.
     */
    if (vmi->num_vcpus < 7) {
        rc = xen->libxcw.xc_evtchn_notify(xe->xce_handle, xe->port);
        if ( rc ) {
            errprint("Error resuming domain.\n");
            return VMI_FAILURE;
        }
    }

    return vrc;
}

status_t xen_init_events(
    vmi_instance_t vmi,
    uint32_t init_flags,
    void *init_data)
{
    xen_events_t * xe = NULL;
    xen_instance_t *xen = xen_get_instance(vmi);
    xc_interface * xch = xen_get_xchandle(vmi);
    domid_t dom = xen_get_domainid(vmi);
    int rc;

#ifdef ENABLE_SAFETY_CHECKS
    if ( !xen ) {
        errprint("%s error: invalid xen_instance_t handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if ( dom == (domid_t)VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return VMI_FAILURE;
    }
#endif

    if ( xen->major_version != 4 || xen->minor_version < 6 ) {
        errprint("%s error: version of Xen is not supported\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    // Allocate memory
    xe = g_malloc0(sizeof(xen_events_t));
    if ( !xe ) {
        errprint("%s error: allocation for xen_events_t failed\n", __FUNCTION__);
        goto err;
    }

    // Enable monitor page
    xe->ring_page = xen->libxcw.xc_monitor_enable(xch, dom, &xe->evtchn_port);
    if ( !xe->ring_page ) {
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

    if ( init_flags & VMI_INIT_XEN_EVTCHN )
        xe->xce_handle = init_data;
    else {
        // Open event channel
        xe->xce_handle = xen->libxcw.xc_evtchn_open(NULL, 0);
        if ( !xe->xce_handle ) {
            errprint("Failed to open event channel\n");
            goto err;
        }
    }

    // Setup poll
    xe->fd.fd = xen->libxcw.xc_evtchn_fd(xe->xce_handle);
    xe->fd.events = POLLIN | POLLERR;

    // Bind event notification
    rc = xen->libxcw.xc_evtchn_bind_interdomain(xe->xce_handle, dom, xe->evtchn_port);
    if ( rc < 0 ) {
        errprint("Failed to bind event channel\n");
        goto err;
    }

    xe->port = rc;
    xe->monitor_mem_access_on = 1;
    xe->process_event[VM_EVENT_REASON_MEM_ACCESS] = &process_mem;
    xe->process_event[VM_EVENT_REASON_WRITE_CTRLREG] = &process_register;
    xe->process_event[VM_EVENT_REASON_MOV_TO_MSR] = &process_register;
    xe->process_event[VM_EVENT_REASON_SOFTWARE_BREAKPOINT] = &process_software_breakpoint;
    xe->process_event[VM_EVENT_REASON_SINGLESTEP] = &process_singlestep;
    xe->process_event[VM_EVENT_REASON_GUEST_REQUEST] = &process_guest_request;
    xe->process_event[VM_EVENT_REASON_DEBUG_EXCEPTION] = &process_debug_exception;
    xe->process_event[VM_EVENT_REASON_CPUID] = &process_cpuid;
    xe->process_event[VM_EVENT_REASON_PRIVILEGED_CALL] = &process_privcall;
    xe->process_event[VM_EVENT_REASON_INTERRUPT] = &process_interrupt;
    xe->process_event[VM_EVENT_REASON_DESCRIPTOR_ACCESS] = &process_desc_access;
    xe->process_event[VM_EVENT_REASON_EMUL_UNIMPLEMENTED] = &process_unimplemented_emul;

    vmi->driver.events_listen_ptr = &xen_events_listen;
    vmi->driver.set_reg_access_ptr = &xen_set_reg_access;
    vmi->driver.set_intr_access_ptr = &xen_set_intr_access;
    vmi->driver.set_mem_access_ptr = &xen_set_mem_access;
    vmi->driver.start_single_step_ptr = &xen_start_single_step;
    vmi->driver.stop_single_step_ptr = &xen_stop_single_step;
    vmi->driver.shutdown_single_step_ptr = &xen_shutdown_single_step;
    vmi->driver.set_guest_requested_ptr = &xen_set_guest_requested_event;
    vmi->driver.set_cpuid_event_ptr = &xen_set_cpuid_event;
    vmi->driver.set_debug_event_ptr = &xen_set_debug_event;
    vmi->driver.set_privcall_event_ptr = &xen_set_privcall_event;
    vmi->driver.set_desc_access_event_ptr = &xen_set_desc_access_event;
    vmi->driver.set_failed_emulation_event_ptr = &xen_set_failed_emulation_event;

    xen->libxcw.xc_monitor_get_capabilities(xch, dom, &xe->monitor_capabilities);
    xen->events = xe;

    dbprint(VMI_DEBUG_XEN, "--Xen common events interface initialized\n");

    switch (xen->minor_version) {
        case 6 ... 7:
            return init_events_46(vmi);
        case 8 ... 11: // fall-through
        default:
            return init_events_48(vmi);
    };

err:
    g_free(xe);
    return VMI_FAILURE;
}

void xen_events_destroy(vmi_instance_t vmi)
{
    int rc, resume = 0;
    xc_interface * xch = xen_get_xchandle(vmi);
    xen_instance_t *xen = xen_get_instance(vmi);
    xen_events_t * xe = xen_get_events(vmi);
    domid_t dom = xen_get_domainid(vmi);

#ifdef ENABLE_SAFETY_CHECKS
    if ( !xen ) {
        errprint("%s error: invalid xen_instance_t handle\n", __FUNCTION__);
        return;
    }
    if ( !xch ) {
        errprint("%s error: invalid xc_interface handle\n", __FUNCTION__);
        return;
    }
    if ( !xe ) {
        errprint("%s error: invalid xen_events_t handle\n", __FUNCTION__);
        return;
    }
    if ( dom == (domid_t)VMI_INVALID_DOMID ) {
        errprint("%s error: invalid domid\n", __FUNCTION__);
        return;
    }
#endif

    xc_dominfo_t info = {0};
    rc = xen->libxcw.xc_domain_getinfo(xch, dom, 1, &info);

    if (rc==1 && info.domid==dom && !info.paused && VMI_SUCCESS == vmi_pause_vm(vmi)) {
        resume = 1;
    }

    // Shutdown all events to make sure VM is in a stable state
    (void)xen->libxcw.xc_set_mem_access(xch, dom, XENMEM_access_rwx, ~0ull, 0);
    (void)xen->libxcw.xc_set_mem_access(xch, dom, XENMEM_access_rwx, 0, xen->max_gpfn);
#if defined(I386) || defined(X86_64)
    if ( xe->monitor_cr0_on )
        (void)xen->libxcw.xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR0, false, false, false);
    if ( xe->monitor_cr3_on )
        (void)xen->libxcw.xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR3, false, false, false);
    if ( xe->monitor_cr4_on )
        (void)xen->libxcw.xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_CR4, false, false, false);
    if ( xe->monitor_xcr0_on )
        (void)xen->libxcw.xc_monitor_write_ctrlreg(xch, dom, VM_EVENT_X86_XCR0, false, false, false);
    if ( xe->monitor_intr_on )
        (void)xen->libxcw.xc_monitor_software_breakpoint(xch, dom, false);
    if ( xe->monitor_singlestep_on )
        (void)driver_shutdown_single_step(vmi);
    if ( vmi->cpuid_event )
        (void)driver_set_cpuid_event(vmi, 0);
    if ( vmi->debug_event )
        (void)driver_set_debug_event(vmi, 0);
    if ( vmi->guest_requested_event )
        (void)driver_set_guest_requested_event(vmi, 0);
    if ( vmi->failed_emulation_event )
        (void)driver_set_failed_emulation_event(vmi, 0);
    if ( xe->monitor_msr_on ) {
        reg_event_t event = { .reg = MSR_ALL, .in_access = VMI_REGACCESS_N };
        (void)driver_set_reg_access(vmi, &event);
    }
#elif defined(ARM32) || defined(ARM64)
    if ( vmi->privcall_event )
        (void)xen->libxcw.xc_monitor_privileged_call(xch, dom, false);
#endif

    if ( driver_are_events_pending(vmi) ) {
        xen_events_listen(vmi, 0);

#if defined(I386) || defined(X86_64)
        /*
         * An event response may still have turned singlestep on
         * so we ensure all vCPUs are clear again.
         */
        driver_shutdown_single_step(vmi);
#endif
    }

    if ( xe->ring_page )
        munmap(xe->ring_page, getpagesize());

    if ( xen->libxcw.xc_monitor_disable(xch, dom) )
        errprint("%s error: couldn't disable monitor vm_event ring.\n", __FUNCTION__);

    // Unbind VIRQ
    if ( xe->port > 0 )
        if ( xen->libxcw.xc_evtchn_unbind(xe->xce_handle, xe->port) )
            errprint("%s error: couldn't unbind event port.\n", __FUNCTION__);

    // Close event channel
    if ( xe->xce_handle )
        if ( xen->libxcw.xc_evtchn_close(xe->xce_handle) )
            errprint("%s error: couldn't close event channel.\n", __FUNCTION__);

    g_free(xe);
    xen_get_instance(vmi)->events = NULL;

    if (resume)
        vmi_resume_vm(vmi);
}

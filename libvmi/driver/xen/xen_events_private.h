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

#include "arch/intel.h"
#include "xen_events_abi.h"
#include "xs_events.h"

/*
 * We use the following structure to map all events to regardless
 * of what ABI version Xen is at. This enables us to avoid having
 * code-duplication for each ABI revision by mapping to this
 * internal-only structure.
 */
typedef struct vm_event_compat {
    uint32_t version;
    uint32_t flags;
    uint32_t reason;
    uint32_t vcpu_id;
    page_mode_t pm;
    uint16_t altp2m_idx;

    union {
        struct vm_event_mem_access            mem_access;
        struct vm_event_write_ctrlreg         write_ctrlreg;
        struct vm_event_mov_to_msr_3          mov_to_msr;
        struct vm_event_desc_access_3         desc_access;
        struct vm_event_singlestep            singlestep;
        struct vm_event_fast_singlestep       fast_singlestep;
        struct vm_event_debug_6               software_breakpoint;
        struct vm_event_debug_6               debug_exception;
        struct vm_event_cpuid                 cpuid;
        struct vm_event_interrupt_x86         x86_interrupt;
        struct vm_event_vmexit                vmexit;
    };

    union {
        union {
            x86_registers_t x86;
            arm_registers_t arm;
        } regs;

        union {
            struct vm_event_emul_read_data_4 read;
            struct vm_event_emul_insn_data insn;
        } emul;
    } data;
} vm_event_compat_t;

typedef struct {
    xc_evtchn* xce_handle;
    int port;
#ifdef HAVE_LIBXENSTORE
    struct pollfd fd[2];
#else
    struct pollfd fd[1];
#endif

    const uint16_t fd_size;
    uint32_t evtchn_port;
    bool external_poll;
    void *ring_page;
    union {
        vm_event_1_back_ring_t back_ring_1;
        vm_event_2_back_ring_t back_ring_2;
        vm_event_3_back_ring_t back_ring_3;
        vm_event_4_back_ring_t back_ring_4;
        vm_event_5_back_ring_t back_ring_5;
        vm_event_6_back_ring_t back_ring_6;
        vm_event_7_back_ring_t back_ring_7;
    };
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

    status_t (*process_requests)(vmi_instance_t vmi, uint32_t *requests_processed);
    status_t (*process_event[__VM_EVENT_REASON_MAX])(vmi_instance_t vmi, vm_event_compat_t *vmec);

#ifdef HAVE_LIBXENSTORE
    status_t (*process_xs_event[__XS_EVENT_REASON_MAX])(vmi_instance_t vmi);
#endif

} xen_events_t;

/* Conversion matrix from LibVMI flags to Xen vm_event flags */
static const unsigned int event_response_conversion[] = {
    [VMI_EVENT_RESPONSE_EMULATE] = VM_EVENT_FLAG_EMULATE,
    [VMI_EVENT_RESPONSE_EMULATE_NOWRITE] = VM_EVENT_FLAG_EMULATE | VM_EVENT_FLAG_EMULATE_NOWRITE,
    [VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP] = VM_EVENT_FLAG_TOGGLE_SINGLESTEP,
    [VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA] = VM_EVENT_FLAG_SET_EMUL_READ_DATA,
    [VMI_EVENT_RESPONSE_DENY] = VM_EVENT_FLAG_DENY,
    [VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID] = VM_EVENT_FLAG_ALTERNATE_P2M,
    [VMI_EVENT_RESPONSE_SET_REGISTERS] = VM_EVENT_FLAG_SET_REGISTERS,
    [VMI_EVENT_RESPONSE_SET_EMUL_INSN] = VM_EVENT_FLAG_SET_EMUL_INSN_DATA,
    [VMI_EVENT_RESPONSE_GET_NEXT_INTERRUPT] = VM_EVENT_FLAG_GET_NEXT_INTERRUPT,
    [VMI_EVENT_RESPONSE_NEXT_SLAT_ID] = VM_EVENT_FLAG_FAST_SINGLESTEP,
    [VMI_EVENT_RESPONSE_RESET_VMTRACE] = VM_EVENT_FLAG_RESET_VMTRACE,
    [VMI_EVENT_RESPONSE_RESET_FORK_MEM] = VM_EVENT_FLAG_RESET_FORK_MEMORY,
    [VMI_EVENT_RESPONSE_RESET_FORK_STATE] = VM_EVENT_FLAG_RESET_FORK_STATE,
};

static inline status_t
convert_vmi_flags_to_xenmem(vmi_mem_access_t page_access_flag, xenmem_access_t *access)
{
    if ( VMI_FAILURE == intel_mem_access_sanity_check(page_access_flag) )
        return VMI_FAILURE;

    switch ( page_access_flag ) {
        case VMI_MEMACCESS_N:
            *access = XENMEM_access_rwx;
            break;
        case VMI_MEMACCESS_W:
            *access = XENMEM_access_rx;
            break;
        case VMI_MEMACCESS_X:
            *access = XENMEM_access_rw;
            break;
        case VMI_MEMACCESS_RW:
            *access = XENMEM_access_x;
            break;
        case VMI_MEMACCESS_WX:
            *access = XENMEM_access_r;
            break;
        case VMI_MEMACCESS_RWX:
            *access = XENMEM_access_n;
            break;
        case VMI_MEMACCESS_W2X:
            *access = XENMEM_access_rx2rw;
            break;
        case VMI_MEMACCESS_RWX2N:
            *access = XENMEM_access_n2rwx;
            break;
        default:
            errprint("%s error: invalid memaccess setting requested\n", __FUNCTION__);
            return VMI_FAILURE;
    };

    return VMI_SUCCESS;
}

#endif

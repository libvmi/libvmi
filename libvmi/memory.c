/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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

#include <stdlib.h>

#include "private.h"
#include "driver/driver_wrapper.h"
#include "arch/arch_interface.h"

/*
 * check that this vm uses a paging method that we support
 * and set pm/cr3/pae/pse/lme flags optionally on the given pointers
 */
status_t probe_memory_layout_x86(vmi_instance_t vmi, unsigned long vcpu, page_mode_t *out_pm)
{
    // To get the paging layout, the following bits are needed:
    // 1. CR0.PG
    // 2. CR4.PAE
    // 3. Either (a) IA32_EFER.LME, or (b) the guest's address width (32 or
    //    64). Not all backends allow us to read an MSR; in particular, Xen's PV
    //    backend doessn't.

    status_t ret = VMI_FAILURE;
    page_mode_t pm = VMI_PM_UNKNOWN;

    /* pull info from registers, if we can */
    reg_t cr0, cr3, cr4, efer;
    int pae = 0, pse = 0, lme = 0;

    /* get the control register values */
    if (driver_get_vcpureg(vmi, &cr0, CR0, vcpu) == VMI_FAILURE) {
        errprint("**failed to get CR0\n");
        goto _exit;
    }

    /* PG Flag --> CR0, bit 31 == 1 --> paging enabled */
    if (!VMI_GET_BIT(cr0, 31)) {
        dbprint(VMI_DEBUG_CORE, "Paging disabled for this VM, only physical addresses supported.\n");
        vmi->page_mode = VMI_PM_UNKNOWN;
        vmi->x86.pse = 0;

        ret = VMI_SUCCESS;
        goto _exit;
    }

    //
    // Paging enabled (PG==1)
    //
    if (driver_get_vcpureg(vmi, &cr4, CR4, vcpu) == VMI_FAILURE) {
        errprint("**failed to get CR4\n");
        goto _exit;
    }

    /* PSE Flag --> CR4, bit 5 */
    pae = VMI_GET_BIT(cr4, 5);
    dbprint(VMI_DEBUG_CORE, "**set pae = %d\n", pae);

    /* PSE Flag --> CR4, bit 4 */
    pse = VMI_GET_BIT(cr4, 4);
    dbprint(VMI_DEBUG_CORE, "**set pse = %d\n", pse);

    if (VMI_SUCCESS == driver_get_vcpureg(vmi, &efer, MSR_EFER, vcpu)) {
        lme = VMI_GET_BIT(efer, 8);
        dbprint(VMI_DEBUG_CORE, "**set lme = %d\n", lme);
    } else if ( vmi->vm_type == PV64 ) {
        lme = 1;
        dbprint(VMI_DEBUG_CORE, "**set lme = %d\n", lme);
    }

    // Get current cr3 for sanity checking
    if (driver_get_vcpureg(vmi, &cr3, CR3, vcpu) == VMI_FAILURE) {
        errprint("**failed to get CR3\n");
        goto _exit;
    }

    // now determine addressing mode
    if (0 == pae) {
        dbprint(VMI_DEBUG_CORE, "**32-bit paging\n");
        pm = VMI_PM_LEGACY;
        cr3 &= 0xFFFFF000ull;
    }
    // PAE == 1; determine IA-32e or PAE
    else if (lme) {    // PAE == 1, LME == 1
        dbprint(VMI_DEBUG_CORE, "**IA-32e paging\n");
        pm = VMI_PM_IA32E;
        cr3 &= 0xFFFFFFFFFFFFF000ull;
    } else {  // PAE == 1, LME == 0
        dbprint(VMI_DEBUG_CORE, "**PAE paging\n");
        pm = VMI_PM_PAE;
        cr3 &= 0xFFFFFFE0;
    }   // if-else
    dbprint(VMI_DEBUG_CORE, "**sanity checking cr3 = 0x%.16"PRIx64"\n", cr3);

    /* testing to see CR3 value */
    if (!driver_is_pv(vmi) && cr3 >= vmi->max_physical_address) {   // sanity check on CR3
        dbprint(VMI_DEBUG_CORE, "** Note cr3 value [0x%"PRIx64"] exceeds max_physical_address [0x%"PRIx64"]\n",
                cr3, vmi->max_physical_address);
    }

    if ( out_pm ) {
        *out_pm = pm;
    } else {
        vmi->page_mode = pm;
        vmi->x86.pse = pse;
    }

    ret = VMI_SUCCESS;

_exit:
    return ret;
}

status_t probe_memory_layout_arm(vmi_instance_t vmi, unsigned long vcpu, page_mode_t *out_pm)
{
    //Note: this will need to be a more comprehensive check when we start supporting AArch64
    status_t ret = VMI_FAILURE;
    page_mode_t pm = VMI_PM_UNKNOWN;

    reg_t cpsr;
    if (VMI_SUCCESS == driver_get_vcpureg(vmi, &cpsr, CPSR, vcpu)) {
        if (cpsr & PSR_MODE_BIT) {
            pm = VMI_PM_AARCH32;
            dbprint(VMI_DEBUG_CORE, "Found ARM32 pagemode\n");
        } else {
            /* See ARM ARMv8-A D7.2.84 TCR_EL1, Translation Control Register (EL1) */
            reg_t tcr_el1;
            if ( !out_pm && VMI_SUCCESS == driver_get_vcpureg(vmi, &tcr_el1, TCR_EL1, vcpu)) {
                vmi->arm64.t0sz = tcr_el1 & VMI_BIT_MASK(0,5);
                vmi->arm64.t1sz = (tcr_el1 & VMI_BIT_MASK(16,21)) >> 16;
                switch ((tcr_el1 & VMI_BIT_MASK(14,15)) >> 14) {
                    case 0b00:
                        vmi->arm64.tg0 = VMI_PS_4KB;
                        break;
                    case 0b01:
                        vmi->arm64.tg0 = VMI_PS_64KB;
                        break;
                    case 0b10:
                        vmi->arm64.tg0 = VMI_PS_16KB;
                        break;
                };
                switch ((tcr_el1 & VMI_BIT_MASK(30,31)) >> 30) {
                    case 0b01:
                        vmi->arm64.tg1 = VMI_PS_16KB;
                        break;
                    case 0b10:
                        vmi->arm64.tg1 = VMI_PS_4KB;
                        break;
                    case 0b11:
                        vmi->arm64.tg1 = VMI_PS_64KB;
                        break;
                };
            }

            pm = VMI_PM_AARCH64;
            dbprint(VMI_DEBUG_CORE,
                    "Found ARM64 pagemode. TTBR0 VA width: %u Page size: %u TTBR1 VA width:%u Page size: %u\n",
                    64-vmi->arm64.t0sz, vmi->arm64.tg0,
                    64-vmi->arm64.t1sz, vmi->arm64.tg1);
        }

        ret = VMI_SUCCESS;
    }

    if ( VMI_SUCCESS == ret ) {
        if ( out_pm )
            *out_pm = pm;
        else
            vmi->page_mode = pm;
    }

    return ret;
}

/*
 * This function attempts to probe the memory layout
 * of a live VM to find the correct page mode.
 */
status_t find_page_mode_live(vmi_instance_t vmi, unsigned long vcpu, page_mode_t *out_pm)
{
    if (VMI_FILE == vmi->mode) {
        /* skip all of this for files */
        return VMI_FAILURE;
    }

#if defined(I386) || defined(X86_64)
    if (VMI_SUCCESS == probe_memory_layout_x86(vmi, vcpu, out_pm)) {
        return VMI_SUCCESS;
    }
#elif defined(ARM32) || defined(ARM64)
    if (VMI_SUCCESS == probe_memory_layout_arm(vmi, vcpu, out_pm)) {
        return VMI_SUCCESS;
    }
#endif

    return VMI_FAILURE;
}

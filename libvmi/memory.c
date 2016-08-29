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
status_t probe_memory_layout_x86(vmi_instance_t vmi) {
    // To get the paging layout, the following bits are needed:
    // 1. CR0.PG
    // 2. CR4.PAE
    // 3. Either (a) IA32_EFER.LME, or (b) the guest's address width (32 or
    //    64). Not all backends allow us to read an MSR; in particular, Xen's PV
    //    backend doessn't.

    status_t ret = VMI_FAILURE;
    page_mode_t pm = VMI_PM_UNKNOWN;
    uint8_t dom_addr_width = 0; // domain address width (bytes)

    /* pull info from registers, if we can */
    reg_t cr0, cr3, cr4, efer;
    int pae = 0, pse = 0, lme = 0;

    /* get the control register values */
    if (driver_get_vcpureg(vmi, &cr0, CR0, 0) == VMI_FAILURE) {
        errprint("**failed to get CR0\n");
        goto _exit;
    }

    /* PG Flag --> CR0, bit 31 == 1 --> paging enabled */
    if (!VMI_GET_BIT(cr0, 31)) {
        dbprint(VMI_DEBUG_CORE, "Paging disabled for this VM, only physical addresses supported.\n");
        vmi->page_mode = VMI_PM_UNKNOWN;
        vmi->x86.pae = 0;
        vmi->x86.pse = 0;
        vmi->x86.lme = 0;

        ret = VMI_SUCCESS;
        goto _exit;
    }

    //
    // Paging enabled (PG==1)
    //
    if (driver_get_vcpureg(vmi, &cr4, CR4, 0) == VMI_FAILURE) {
        errprint("**failed to get CR4\n");
        goto _exit;
    }

    /* PSE Flag --> CR4, bit 5 */
    pae = VMI_GET_BIT(cr4, 5);
    dbprint(VMI_DEBUG_CORE, "**set pae = %d\n", pae);

    /* PSE Flag --> CR4, bit 4 */
    pse = VMI_GET_BIT(cr4, 4);
    dbprint(VMI_DEBUG_CORE, "**set pse = %d\n", pse);

    ret = driver_get_vcpureg(vmi, &efer, MSR_EFER, 0);
    if (VMI_SUCCESS == ret) {
        lme = VMI_GET_BIT(efer, 8);
        dbprint(VMI_DEBUG_CORE, "**set lme = %d\n", lme);
    } else {
        dbprint(VMI_DEBUG_CORE, "**failed to get MSR_EFER, trying method #2\n");

        // does this trick work in all cases?
        ret = driver_get_address_width(vmi, &dom_addr_width);
        if (VMI_FAILURE == ret) {
            errprint
                ("Failed to get domain address width. Giving up.\n");
            goto _exit;
        }
        lme = (8 == dom_addr_width);
        dbprint
            (VMI_DEBUG_CORE, "**found guest address width is %d bytes; assuming IA32_EFER.LME = %d\n",
             dom_addr_width, lme);
    }   // if
    // Get current cr3 for sanity checking
    if (driver_get_vcpureg(vmi, &cr3, CR3, 0) == VMI_FAILURE) {
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

    vmi->page_mode = pm;
    vmi->x86.pae = pae;
    vmi->x86.pse = pse;
    vmi->x86.lme = lme;

_exit:
    return ret;
}

status_t probe_memory_layout_arm(vmi_instance_t vmi) {
    //Note: this will need to be a more comprehensive check when we start supporting AArch64
    status_t ret = VMI_FAILURE;
    page_mode_t pm = VMI_PM_UNKNOWN;

    reg_t cpsr;
    if (VMI_SUCCESS == driver_get_vcpureg(vmi, &cpsr, CPSR, 0)) {
        if (cpsr & PSR_MODE_BIT) {
            pm = VMI_PM_AARCH32;
            dbprint(VMI_DEBUG_CORE, "Found ARM32 pagemode\n");
        } else {
            /* See ARM ARMv8-A D7.2.84 TCR_EL1, Translation Control Register (EL1) */
            reg_t tcr_el1;
            if (VMI_SUCCESS == driver_get_vcpureg(vmi, &tcr_el1, TCR_EL1, 0)) {
                vmi->arm64.t0sz = tcr_el1 & VMI_BIT_MASK(0,5);
                vmi->arm64.t1sz = (tcr_el1 & VMI_BIT_MASK(16,21)) >> 16;
                switch((tcr_el1 & VMI_BIT_MASK(14,15)) >> 14) {
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
                switch((tcr_el1 & VMI_BIT_MASK(30,31)) >> 30) {
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

    vmi->page_mode = pm;
    return ret;
}

/*
 * This function attempts to probe the memory layout
 * of a live VM to find the correct page mode.
 */
status_t find_page_mode_live(vmi_instance_t vmi) {
    if (VMI_FILE == vmi->mode) {
        /* skip all of this for files */
        return VMI_FAILURE;
    }

#if defined(I386) || defined(X86_64)
    if (VMI_SUCCESS == probe_memory_layout_x86(vmi)) {
        return VMI_SUCCESS;
    }
#elif defined(ARM32) || defined(ARM64)
    if (VMI_SUCCESS == probe_memory_layout_arm(vmi)) {
        return VMI_SUCCESS;
    }
#endif

    return VMI_FAILURE;
}

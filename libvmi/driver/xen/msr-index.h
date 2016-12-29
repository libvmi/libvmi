/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
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
#ifndef MSR_INDEX_H
#define MSR_INDEX_H

const reg_t msr_all[] = {
    MSR_EFER,
    MSR_STAR,
    MSR_LSTAR,
    MSR_CSTAR,
    MSR_SYSCALL_MASK,
    MSR_SHADOW_GS_BASE,
    MSR_TSC_AUX,

    MSR_MTRRfix64K_00000,
    MSR_MTRRfix16K_80000,
    MSR_MTRRfix16K_A0000,
    MSR_MTRRfix4K_C0000,
    MSR_MTRRfix4K_C8000,
    MSR_MTRRfix4K_D0000,
    MSR_MTRRfix4K_D8000,
    MSR_MTRRfix4K_E0000,
    MSR_MTRRfix4K_E8000,
    MSR_MTRRfix4K_F0000,
    MSR_MTRRfix4K_F8000,
    MSR_MTRRdefType,

    MSR_IA32_MC0_CTL,
    MSR_IA32_MC0_STATUS,
    MSR_IA32_MC0_ADDR,
    MSR_IA32_MC0_MISC,
    MSR_IA32_MC1_CTL,
    MSR_IA32_MC0_CTL2,

    MSR_AMD_PATCHLEVEL,

    MSR_AMD64_TSC_RATIO,

    MSR_IA32_P5_MC_ADDR,
    MSR_IA32_P5_MC_TYPE,
    MSR_IA32_TSC,
    MSR_IA32_PLATFORM_ID,
    MSR_IA32_EBL_CR_POWERON,
    MSR_IA32_EBC_FREQUENCY_ID,

    MSR_IA32_FEATURE_CONTROL,

    MSR_IA32_SYSENTER_CS,
    MSR_IA32_SYSENTER_ESP,
    MSR_IA32_SYSENTER_EIP,

    MSR_IA32_MISC_ENABLE,

    MSR_HYPERVISOR,
};

const uint32_t msr_index[] = {
    [MSR_EFER]                   = 0xc0000080, /* extended feature register */
    [MSR_STAR]                   = 0xc0000081, /* legacy mode SYSCALL target */
    [MSR_LSTAR]                  = 0xc0000082, /* long mode SYSCALL target */
    [MSR_CSTAR]                  = 0xc0000083, /* compat mode SYSCALL target */
    [MSR_SYSCALL_MASK]           = 0xc0000084, /* EFLAGS mask for syscall */
    [MSR_SHADOW_GS_BASE]         = 0xc0000102, /* SwapGS GS shadow */
    [MSR_TSC_AUX]                = 0xc0000103, /* Auxiliary TSC */

    [MSR_MTRRfix64K_00000]       = 0x00000250,
    [MSR_MTRRfix16K_80000]       = 0x00000258,
    [MSR_MTRRfix16K_A0000]       = 0x00000259,
    [MSR_MTRRfix4K_C0000]        = 0x00000268,
    [MSR_MTRRfix4K_C8000]        = 0x00000269,
    [MSR_MTRRfix4K_D0000]        = 0x0000026a,
    [MSR_MTRRfix4K_D8000]        = 0x0000026b,
    [MSR_MTRRfix4K_E0000]        = 0x0000026c,
    [MSR_MTRRfix4K_E8000]        = 0x0000026d,
    [MSR_MTRRfix4K_F0000]        = 0x0000026e,
    [MSR_MTRRfix4K_F8000]        = 0x0000026f,
    [MSR_MTRRdefType]            = 0x000002ff,

    [MSR_IA32_MC0_CTL]           = 0x00000400,
    [MSR_IA32_MC0_STATUS]        = 0x00000401,
    [MSR_IA32_MC0_ADDR]          = 0x00000402,
    [MSR_IA32_MC0_MISC]          = 0x00000403,
    [MSR_IA32_MC1_CTL]           = 0x00000404,
    [MSR_IA32_MC0_CTL2]          = 0x00000280,

    [MSR_AMD_PATCHLEVEL]         = 0x0000008b,

    [MSR_AMD64_TSC_RATIO]        = 0xc0000104,

    [MSR_IA32_P5_MC_ADDR]        = 0x00000000,
    [MSR_IA32_P5_MC_TYPE]        = 0x00000001,
    [MSR_IA32_TSC]               = 0x00000010,
    [MSR_IA32_PLATFORM_ID]       = 0x00000017,
    [MSR_IA32_EBL_CR_POWERON]    = 0x0000002a,
    [MSR_IA32_EBC_FREQUENCY_ID]  = 0x0000002c,

    [MSR_IA32_FEATURE_CONTROL]   = 0x0000003a,

    [MSR_IA32_SYSENTER_CS]       = 0x00000174,
    [MSR_IA32_SYSENTER_ESP]      = 0x00000175,
    [MSR_IA32_SYSENTER_EIP]      = 0x00000176,

    [MSR_IA32_MISC_ENABLE]       = 0x000001a0,

    [MSR_HYPERVISOR]             = 0x40000000
};

#endif /* MSR_INDEX_H */

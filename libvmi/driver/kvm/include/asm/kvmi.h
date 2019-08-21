/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_X86_KVMI_H
#define _UAPI_ASM_X86_KVMI_H

/*
 * KVM introspection - x86 specific structures and definitions
 */

#include <asm/kvm.h>

struct kvmi_event_arch {
	__u8 mode;		/* 2, 4 or 8 */
	__u8 padding[7];
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct {
		__u64 sysenter_cs;
		__u64 sysenter_esp;
		__u64 sysenter_eip;
		__u64 efer;
		__u64 star;
		__u64 lstar;
		__u64 cstar;
		__u64 pat;
		__u64 shadow_gs;
	} msrs;
};

struct kvmi_event_trap {
	__u32 vector;
	__u32 type;
	__u32 error_code;
	__u32 padding;
	__u64 cr2;
};

struct kvmi_get_registers {
	__u16 nmsrs;
	__u16 padding1;
	__u32 padding2;
	__u32 msrs_idx[0];
};

struct kvmi_get_registers_reply {
	__u32 mode;
	__u32 padding;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_msrs msrs;
};

struct kvmi_get_cpuid {
	__u32 function;
	__u32 index;
};

struct kvmi_get_cpuid_reply {
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
};

struct kvmi_control_cr {
	__u8 enable;
	__u8 padding1;
	__u16 padding2;
	__u32 cr;
};

struct kvmi_event_cr {
	__u16 cr;
	__u16 padding[3];
	__u64 old_value;
	__u64 new_value;
};

struct kvmi_event_cr_reply {
	__u64 new_val;
};

struct kvmi_control_msr {
	__u8 enable;
	__u8 padding1;
	__u16 padding2;
	__u32 msr;
};

struct kvmi_event_msr {
	__u32 msr;
	__u32 padding;
	__u64 old_value;
	__u64 new_value;
};

struct kvmi_event_msr_reply {
	__u64 new_val;
};

struct kvmi_get_xsave_reply {
	__u32 region[0];
};

struct kvmi_get_mtrr_type {
	__u64 gpa;
};

struct kvmi_get_mtrr_type_reply {
	__u8 type;
	__u8 padding[7];
};

#define KVMI_DESC_IDTR	1
#define KVMI_DESC_GDTR	2
#define KVMI_DESC_LDTR	3
#define KVMI_DESC_TR	4

struct kvmi_event_descriptor {
	__u8 descriptor;
	__u8 write;
	__u8 padding[6];
};

#endif /* _UAPI_ASM_X86_KVMI_H */

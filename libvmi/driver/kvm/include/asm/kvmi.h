/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASM_X86_KVMI_H
#define _ASM_X86_KVMI_H

/*
 * KVMI x86 specific structures and definitions
 *
 */

#include <asm/kvm.h>
#include <linux/types.h>

#define KVMI_EVENT_CR          (1 << 1)	/* control register was modified */
#define KVMI_EVENT_MSR         (1 << 2)	/* model specific reg. was modified */
#define KVMI_EVENT_XSETBV      (1 << 3)	/* ext. control register was modified */
#define KVMI_EVENT_BREAKPOINT  (1 << 4)	/* breakpoint was reached */
#define KVMI_EVENT_HYPERCALL   (1 << 5)	/* user hypercall */
#define KVMI_EVENT_PAGE_FAULT  (1 << 6)	/* hyp. page fault was encountered */
#define KVMI_EVENT_TRAP        (1 << 7)	/* trap was injected */
#define KVMI_EVENT_DESCRIPTOR  (1 << 8)	/* descriptor table access */
#define KVMI_EVENT_CREATE_VCPU (1 << 9)
#define KVMI_EVENT_PAUSE_VCPU  (1 << 10)

/* TODO: find a way to split the events between common and arch dependent */

#define KVMI_EVENT_ACTION_CONTINUE (1 << 0)
#define KVMI_EVENT_ACTION_RETRY    (1 << 1)
#define KVMI_EVENT_ACTION_CRASH    (1 << 2)

#define KVMI_KNOWN_EVENTS (KVMI_EVENT_CR | \
			   KVMI_EVENT_MSR | \
			   KVMI_EVENT_XSETBV | \
			   KVMI_EVENT_BREAKPOINT | \
			   KVMI_EVENT_HYPERCALL | \
			   KVMI_EVENT_PAGE_FAULT | \
			   KVMI_EVENT_TRAP | \
			   KVMI_EVENT_CREATE_VCPU | \
			   KVMI_EVENT_PAUSE_VCPU | \
			   KVMI_EVENT_DESCRIPTOR)

#define KVMI_ALLOWED_EVENT(event_id, event_mask)                       \
		((!(event_id)) || (                                    \
			(event_id)                                     \
				& ((event_mask) & KVMI_KNOWN_EVENTS)))

#define KVMI_PAGE_ACCESS_R (1 << 0)
#define KVMI_PAGE_ACCESS_W (1 << 1)
#define KVMI_PAGE_ACCESS_X (1 << 2)

struct kvmi_event_cr {
	__u16 cr;
	__u16 padding[3];
	__u64 old_value;
	__u64 new_value;
};

struct kvmi_event_msr {
	__u32 msr;
	__u32 padding;
	__u64 old_value;
	__u64 new_value;
};

struct kvmi_event_breakpoint {
	__u64 gpa;
};

struct kvmi_event_page_fault {
	__u64 gva;
	__u64 gpa;
	__u32 mode;
	__u32 padding;
};

struct kvmi_event_trap {
	__u32 vector;
	__u32 type;
	__u32 error_code;
	__u32 padding;
	__u64 cr2;
};

#define KVMI_DESC_IDTR	1
#define KVMI_DESC_GDTR	2
#define KVMI_DESC_LDTR	3
#define KVMI_DESC_TR	4

struct kvmi_event_descriptor {
	union {
		struct {
			__u32 instr_info;
			__u32 padding;
			__u64 exit_qualification;
		} vmx;
		struct {
			__u64 exit_info;
			__u64 padding;
		} svm;
	} arch;
	__u8 descriptor;
	__u8 write;
	__u8 padding[6];
};

struct kvmi_event {
	__u32 event;
	__u16 vcpu;
	__u8 mode;		/* 2, 4 or 8 */
	__u8 padding;
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
	} msrs;
};

struct kvmi_event_cr_reply {
	__u64 new_val;
};

struct kvmi_event_msr_reply {
	__u64 new_val;
};

struct kvmi_event_page_fault_reply {
	__u8 trap_access;
	__u8 padding[3];
	__u32 ctx_size;
	__u8 ctx_data[256];
};

struct kvmi_control_cr {
	__u16 vcpu;
	__u8 enable;
	__u8 padding;
	__u32 cr;
};

struct kvmi_control_msr {
	__u16 vcpu;
	__u8 enable;
	__u8 padding;
	__u32 msr;
};

struct kvmi_guest_info {
	__u16 vcpu_count;
	__u16 padding1;
	__u32 padding2;
	__u64 tsc_speed;
};

struct kvmi_inject_exception {
	__u16 vcpu;
	__u8 nr;
	__u8 has_error;
	__u16 error_code;
	__u16 padding;
	__u64 address;
};

struct kvmi_get_registers {
	__u16 vcpu;
	__u16 nmsrs;
	__u16 padding[2];
	__u32 msrs_idx[0];
};

struct kvmi_get_registers_reply {
	__u32 mode;
	__u32 padding;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_msrs msrs;
};

struct kvmi_set_registers {
	__u16 vcpu;
	__u16 padding[3];
	struct kvm_regs regs;
};

struct kvmi_get_cpuid {
	__u16 vcpu;
	__u16 padding[3];
	__u32 function;
	__u32 index;
};

struct kvmi_get_cpuid_reply {
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
};

struct kvmi_get_xsave {
	__u16 vcpu;
	__u16 padding[3];
};

struct kvmi_get_xsave_reply {
	__u32 region[0];
};

#endif /* _ASM_X86_KVMI_H */

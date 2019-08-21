/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_KVMI_H
#define _UAPI__LINUX_KVMI_H

/*
 * KVMI structures and definitions
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/kvmi.h>

#define KVMI_VERSION 0x00000001

enum {
	KVMI_EVENT_REPLY           = 0,
	KVMI_EVENT                 = 1,

	KVMI_FIRST_COMMAND         = 2,

	KVMI_GET_VERSION           = 2,
	KVMI_CHECK_COMMAND         = 3,
	KVMI_CHECK_EVENT           = 4,
	KVMI_GET_GUEST_INFO        = 5,
	KVMI_GET_VCPU_INFO         = 6,
	KVMI_PAUSE_VCPU            = 7,
	KVMI_CONTROL_VM_EVENTS     = 8,
	KVMI_CONTROL_EVENTS        = 9,
	KVMI_CONTROL_CR            = 10,
	KVMI_CONTROL_MSR           = 11,
	KVMI_CONTROL_VE            = 12,
	KVMI_GET_REGISTERS         = 13,
	KVMI_SET_REGISTERS         = 14,
	KVMI_GET_CPUID             = 15,
	KVMI_GET_XSAVE             = 16,
	KVMI_READ_PHYSICAL         = 17,
	KVMI_WRITE_PHYSICAL        = 18,
	KVMI_INJECT_EXCEPTION      = 19,
	KVMI_GET_PAGE_ACCESS       = 20,
	KVMI_SET_PAGE_ACCESS       = 21,
	KVMI_GET_MAP_TOKEN         = 22,
	KVMI_GET_MTRR_TYPE         = 23,
	KVMI_CONTROL_SPP           = 24,
	KVMI_GET_PAGE_WRITE_BITMAP = 25,
	KVMI_SET_PAGE_WRITE_BITMAP = 26,
	KVMI_CONTROL_CMD_RESPONSE  = 27,

	KVMI_NEXT_AVAILABLE_COMMAND,

};

enum {
	KVMI_EVENT_UNHOOK      = 0,
	KVMI_EVENT_CR	       = 1,
	KVMI_EVENT_MSR	       = 2,
	KVMI_EVENT_XSETBV      = 3,
	KVMI_EVENT_BREAKPOINT  = 4,
	KVMI_EVENT_HYPERCALL   = 5,
	KVMI_EVENT_PF	       = 6,
	KVMI_EVENT_TRAP	       = 7,
	KVMI_EVENT_DESCRIPTOR  = 8,
	KVMI_EVENT_CREATE_VCPU = 9,
	KVMI_EVENT_PAUSE_VCPU  = 10,
	KVMI_EVENT_SINGLESTEP  = 11,

	KVMI_NUM_EVENTS
};

#define KVMI_EVENT_ACTION_CONTINUE      0
#define KVMI_EVENT_ACTION_RETRY         1
#define KVMI_EVENT_ACTION_CRASH         2

#define KVMI_PAGE_ACCESS_R (1 << 0)
#define KVMI_PAGE_ACCESS_W (1 << 1)
#define KVMI_PAGE_ACCESS_X (1 << 2)

#define KVMI_MSG_SIZE (4096 - sizeof(struct kvmi_msg_hdr))

struct kvmi_msg_hdr {
	__u16 id;
	__u16 size;
	__u32 seq;
};

struct kvmi_error_code {
	__s32 err;
	__u32 padding;
};

struct kvmi_get_version_reply {
	__u32 version;
	__u32 padding;
};

struct kvmi_control_cmd_response {
	__u8 enable;
	__u8 now;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_check_command {
	__u16 id;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_check_event {
	__u16 id;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_get_guest_info_reply {
	__u32 vcpu_count;
	__u32 padding[3];
};

struct kvmi_get_page_access {
	__u16 view;
	__u16 count;
	__u32 padding;
	__u64 gpa[0];
};

struct kvmi_get_page_access_reply {
	__u8 access[0];
};

struct kvmi_page_access_entry {
	__u64 gpa;
	__u8 access;
	__u8 padding1;
	__u16 padding2;
	__u32 padding3;
};

struct kvmi_set_page_access {
	__u16 view;
	__u16 count;
	__u32 padding;
	struct kvmi_page_access_entry entries[0];
};

struct kvmi_control_spp {
	__u8 enable;
	__u8 padding1;
	__u16 padding2;
	__u32 padding3;
};

struct kvmi_get_page_write_bitmap {
	__u16 view;
	__u16 count;
	__u32 padding;
	__u64 gpa[0];
};

struct kvmi_get_page_write_bitmap_reply {
	__u32 bitmap[0];
};

struct kvmi_page_write_bitmap_entry {
	__u64 gpa;
	__u32 bitmap;
	__u32 padding;
};

struct kvmi_set_page_write_bitmap {
	__u16 view;
	__u16 count;
	__u32 padding;
	struct kvmi_page_write_bitmap_entry entries[0];
};

struct kvmi_get_vcpu_info_reply {
	__u64 tsc_speed;
};

struct kvmi_pause_vcpu {
	__u8 wait;
	__u8 padding1;
	__u16 padding2;
	__u32 padding3;
};

struct kvmi_control_events {
	__u16 event_id;
	__u8 enable;
	__u8 padding1;
	__u32 padding2;
};

struct kvmi_control_vm_events {
	__u16 event_id;
	__u8 enable;
	__u8 padding1;
	__u32 padding2;
};

struct kvmi_read_physical {
	__u64 gpa;
	__u64 size;
};

struct kvmi_write_physical {
	__u64 gpa;
	__u64 size;
	__u8  data[0];
};

struct kvmi_vcpu_hdr {
	__u16 vcpu;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_inject_exception {
	__u8 nr;
	__u8 has_error;
	__u16 padding;
	__u32 error_code;
	__u64 address;
};

struct kvmi_event {
	__u16 size;
	__u16 vcpu;
	__u8 event;
	__u8 padding[3];
	struct kvmi_event_arch arch;
};

struct kvmi_event_reply {
	__u8 action;
	__u8 event;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_event_pf {
	__u64 gva;
	__u64 gpa;
	__u8 access;
	__u8 padding1;
	__u16 view;
	__u32 padding2;
};

struct kvmi_event_pf_reply {
	__u64 ctx_addr;
	__u32 ctx_size;
	__u8 singlestep;
	__u8 rep_complete;
	__u16 padding;
	__u8 ctx_data[256];
};

struct kvmi_event_breakpoint {
	__u64 gpa;
	__u8 insn_len;
	__u8 padding[7];
};

struct kvmi_map_mem_token {
	__u64 token[4];
};

struct kvmi_get_map_token_reply {
	struct kvmi_map_mem_token token;
};

/* Map other guest's gpa to local gva */
struct kvmi_mem_map {
	struct kvmi_map_mem_token token;
	__u64 gpa;
	__u64 gva;
};

/*
 * ioctls for /dev/kvmmem
 */
#define KVM_INTRO_MEM_MAP       _IOW('i', 0x01, struct kvmi_mem_map)
#define KVM_INTRO_MEM_UNMAP     _IOW('i', 0x02, unsigned long)

#endif /* _UAPI__LINUX_KVMI_H */

/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __KVMI_H_INCLUDED__
#define __KVMI_H_INCLUDED__

/*
 * KVMI specific structures and definitions
 *
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/kvmi.h>

#define KVMI_VERSION 0x00000001

#define KVMI_GET_VERSION                  1
#define KVMI_PAUSE_VCPU                   2
#define KVMI_GET_GUEST_INFO               3
#define KVMI_GET_REGISTERS                6
#define KVMI_SET_REGISTERS                7
#define KVMI_GET_PAGE_ACCESS              10
#define KVMI_SET_PAGE_ACCESS              11
#define KVMI_INJECT_EXCEPTION             12
#define KVMI_READ_PHYSICAL                13
#define KVMI_WRITE_PHYSICAL               14
#define KVMI_GET_MAP_TOKEN                15
#define KVMI_CONTROL_EVENTS               17
#define KVMI_CONTROL_CR                   18
#define KVMI_CONTROL_MSR                  19
#define KVMI_EVENT                        23
#define KVMI_EVENT_REPLY                  24
#define KVMI_GET_CPUID                    25
#define KVMI_GET_XSAVE                    26

/* TODO: find a way to split the commands between common and arch dependent */

#define KVMI_KNOWN_COMMANDS (-1) /* TODO: fix me */

#define KVMI_ALLOWED_COMMAND(cmd_id, cmd_mask)                         \
		((!(cmd_id)) || (                                      \
			(1 << ((cmd_id)-1))                            \
				& ((cmd_mask) & KVMI_KNOWN_COMMANDS)))
struct kvmi_msg_hdr {
	__u16 id;
	__u16 size;
	__u32 seq;
};

#define KVMI_MAX_MSG_SIZE (sizeof(struct kvmi_msg_hdr) \
			+ (1 << FIELD_SIZEOF(struct kvmi_msg_hdr, size)*8) \
			- 1)

struct kvmi_error_code {
	__s32 err;
	__u32 padding;
};

struct kvmi_get_version_reply {
	__u32 version;
	__u32 commands;
	__u32 events;
	__u32 padding;
};

struct kvmi_get_guest_info {
	__u16 vcpu;
	__u16 padding[3];
};

struct kvmi_get_guest_info_reply {
	__u16 vcpu_count;
	__u16 padding[3];
	__u64 tsc_speed;
};

struct kvmi_pause_vcpu {
	__u16 vcpu;
	__u16 padding[3];
};

struct kvmi_event_reply {
	__u32 action;
	__u32 padding;
};

struct kvmi_control_events {
	__u16 vcpu;
	__u16 padding;
	__u32 events;
};

struct kvmi_get_page_access {
	__u16 vcpu;
	__u16 count;
	__u16 view;
	__u16 padding;
	__u64 gpa[0];
};

struct kvmi_get_page_access_reply {
	__u8 access[0];
};

struct kvmi_page_access_entry {
	__u64 gpa;
	__u8 access;
	__u8 padding[7];
};

struct kvmi_set_page_access {
	__u16 vcpu;
	__u16 count;
	__u16 view;
	__u16 padding;
	struct kvmi_page_access_entry entries[0];
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
#define KVM_INTRO_MEM_MAP	_IOW('i', 0x01, struct kvmi_mem_map)
#define KVM_INTRO_MEM_UNMAP	_IOW('i', 0x02, unsigned long)

#endif /* __KVMI_H_INCLUDED__ */

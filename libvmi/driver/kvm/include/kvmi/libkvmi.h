/*
 * Copyright (C) 2017-2019 Bitdefender S.R.L.
 *
 * The KVMI Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * The KVMI Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the GNU C Library; if not, see
 * <http://www.gnu.org/licenses/>
 */
#ifndef __LIBKVMI_H_INCLUDED__
#define __LIBKVMI_H_INCLUDED__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <linux/kvmi.h>

typedef int kvmi_timeout_t;

enum {
	KVMI_NOWAIT = 0,
	KVMI_WAIT   = 150
};

struct kvmi_dom_event {
	void *next;
	struct {
		struct kvmi_event common;
		union {
			struct kvmi_event_cr         cr;
			struct kvmi_event_msr        msr;
			struct kvmi_event_breakpoint breakpoint;
			struct kvmi_event_pf         page_fault;
			struct kvmi_event_trap       trap;
			struct kvmi_event_descriptor desc;
		};
	} event;
	unsigned char buf[KVMI_MSG_SIZE];
	unsigned int  seq;
};

struct kvmi_qemu2introspector {
	uint32_t      struct_size;
	unsigned char uuid[16];
	uint32_t      padding;
	int64_t       start_time;
	char          name[64];
	/* ... */
};

struct kvmi_introspector2qemu {
	uint32_t struct_size;
	uint8_t  cookie_hash[20];
	/* ... */
};

typedef enum { KVMI_LOG_LEVEL_DEBUG, KVMI_LOG_LEVEL_INFO, KVMI_LOG_LEVEL_WARNING, KVMI_LOG_LEVEL_ERROR } kvmi_log_level;

typedef void ( *kvmi_log_cb )( kvmi_log_level level, const char *s, void *ctx );

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef int ( *kvmi_new_guest_cb )( void *dom, unsigned char ( *uuid )[16], void *ctx );
typedef int ( *kvmi_handshake_cb )( const struct kvmi_qemu2introspector *, struct kvmi_introspector2qemu *, void *ctx );

void *kvmi_init_vsock( unsigned int port, kvmi_new_guest_cb accept_cb, kvmi_handshake_cb hsk_cb, void *cb_ctx );
void *kvmi_init_unix_socket( const char *socket, kvmi_new_guest_cb accept_cb, kvmi_handshake_cb hsk_cb, void *cb_ctx );
void  kvmi_uninit( void *ctx );
void  kvmi_close( void *ctx );
void  kvmi_domain_close( void *dom, bool do_shutdown );
bool  kvmi_domain_is_connected( const void *dom );
int   kvmi_memory_mapping( void *dom, bool enable );
void  kvmi_domain_name( const void *dom, char *dest, size_t dest_size );
int   kvmi_connection_fd( const void *dom );
int   kvmi_get_version( void *dom, unsigned int *version );
int   kvmi_check_command( void *dom, int id );
int   kvmi_check_event( void *dom, int id );
int   kvmi_control_events( void *dom, unsigned short vcpu, int id, bool enable );
int   kvmi_control_vm_events( void *dom, int id, bool enable );
int   kvmi_control_cr( void *dom, unsigned short vcpu, unsigned int cr, bool enable );
int   kvmi_control_msr( void *dom, unsigned short vcpu, unsigned int msr, bool enable );
int   kvmi_pause_all_vcpus( void *dom, unsigned int count );
int   kvmi_get_page_access( void *dom, unsigned long long int gpa, unsigned char *access );
int   kvmi_get_page_write_bitmap( void *dom, __u64 gpa, __u32 *bitmap );
int   kvmi_set_page_access( void *dom, unsigned long long int *gpa, unsigned char *access, unsigned short count );
int   kvmi_set_page_write_bitmap( void *dom, __u64 *gpa, __u32 *bitmap, unsigned short count );
int   kvmi_get_vcpu_count( void *dom, unsigned int *count );
int64_t kvmi_get_starttime( const void *dom );
int     kvmi_get_tsc_speed( void *dom, unsigned long long int *speed );
int     kvmi_get_cpuid( void *dom, unsigned short vcpu, unsigned int function, unsigned int index, unsigned int *eax,
                        unsigned int *ebx, unsigned int *ecx, unsigned int *edx );
int     kvmi_get_mtrr_type( void *dom, unsigned long long int gpa, unsigned char *type );
int     kvmi_get_xsave( void *dom, unsigned short vcpu, void *buffer, size_t bufSize );
int     kvmi_inject_exception( void *dom, unsigned short vcpu, unsigned long long int gva, unsigned int error, unsigned char vector );
int     kvmi_read_physical( void *dom, unsigned long long int gpa, void *buffer, size_t size );
int     kvmi_write_physical( void *dom, unsigned long long int gpa, const void *buffer, size_t size );
void *  kvmi_map_physical_page( void *dom, unsigned long long int gpa );
int     kvmi_unmap_physical_page( const void *dom, void *addr );
int     kvmi_get_registers( void *dom, unsigned short vcpu, struct kvm_regs *regs, struct kvm_sregs *sregs,
                            struct kvm_msrs *msrs, unsigned int *mode );
int     kvmi_set_registers( void *dom, unsigned short vcpu, const struct kvm_regs *regs );
int     kvmi_shutdown_guest( void *dom );
int     kvmi_reply_event( void *dom, unsigned int msg_seq, const void *data, size_t data_size );
int     kvmi_pop_event( void *dom, struct kvmi_dom_event **event );
int     kvmi_wait_event( void *dom, kvmi_timeout_t ms );
void    kvmi_set_log_cb( kvmi_log_cb cb, void *ctx );
void *  kvmi_batch_alloc( void *dom );
int     kvmi_batch_commit( void *batch );
void    kvmi_batch_free( void *batch );
int     kvmi_queue_registers( void *batch, unsigned short vcpu, const struct kvm_regs *regs );
int     kvmi_queue_reply_event( void *batch, unsigned int msg_seq, const void *data, size_t data_size );
int     kvmi_queue_page_access( void *batch, unsigned long long int *gpa, unsigned char *access, unsigned short count );
int     kvmi_queue_pause_vcpu( void *batch, unsigned short vcpu );
int     kvmi_get_maximum_gfn( void *dom, unsigned long long *gfn );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LIBKVMI_H_INCLUDED__ */

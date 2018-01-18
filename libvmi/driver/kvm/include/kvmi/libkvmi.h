/*
 * Copyright (C) 2017-2018 Bitdefender S.R.L.
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

/* if missing from linux/kernel.h (used by kvmi.h) */
#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF( t, f ) ( sizeof( ( ( t * )0 )->f ) )
#endif

#include <linux/kvmi.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef int ( *kvmi_new_guest_cb )( void *dom, unsigned char ( *uuid )[16], void *ctx );
typedef int ( *kvmi_new_event_cb )( void *dom, unsigned int seq, unsigned int size, void *ctx );

void *kvmi_init_vsock( unsigned int port, kvmi_new_guest_cb cb, kvmi_new_event_cb event_cb, void *cb_ctx );
void *kvmi_init_unix_socket( const char *socket, kvmi_new_guest_cb cb, kvmi_new_event_cb event_cb, void *cb_ctx );
void  kvmi_uninit( void *ctx );
void  kvmi_set_event_cb( void *dom, kvmi_new_event_cb cb, void *cb_ctx );
void  kvmi_domain_close( void *dom );
int   kvmi_connection_fd( void *dom );
int   kvmi_get_version( void *dom, unsigned int *version );
int   kvmi_control_events( void *dom, unsigned short vcpu, unsigned int events );
int   kvmi_control_cr( void *dom, unsigned int cr, bool enable );
int   kvmi_control_msr( void *dom, unsigned int msr, bool enable );
int   kvmi_get_page_access( void *dom, unsigned short vcpu, unsigned long long int gpa, unsigned char *access );
int   kvmi_set_page_access( void *dom, unsigned short vcpu, unsigned long long int *gpa, unsigned char *access,
                            unsigned short count );
int   kvmi_pause_vcpu( void *dom, unsigned short vcpu );
int   kvmi_get_vcpu_count( void *dom, unsigned short *count );
int   kvmi_get_tsc_speed( void *dom, unsigned long long int *speed );
int   kvmi_get_cpuid( void *dom, unsigned short vcpu, unsigned int function, unsigned int index, unsigned int *eax,
                      unsigned int *ebx, unsigned int *ecx, unsigned int *edx );
int   kvmi_get_xsave( void *dom, unsigned short vcpu, void *buffer, size_t bufSize );
int   kvmi_inject_page_fault( void *dom, unsigned short vcpu, unsigned long long int gva, unsigned int error );
int   kvmi_inject_breakpoint( void *dom, unsigned short vcpu );
int   kvmi_read_physical( void *dom, unsigned long long int gpa, void *buffer, size_t size );
int   kvmi_write_physical( void *dom, unsigned long long int gpa, const void *buffer, size_t size );
void *kvmi_map_physical_page( void *dom, unsigned long long int gpa );
int   kvmi_unmap_physical_page( void *dom, void *addr );
int   kvmi_get_registers( void *dom, unsigned short vcpu, struct kvm_regs *regs, struct kvm_sregs *sregs,
                          struct kvm_msrs *msrs, unsigned int *mode );
int   kvmi_set_registers( void *dom, unsigned short vcpu, const struct kvm_regs *regs );
int   kvmi_shutdown_guest( void *dom );
int   kvmi_reply_event( void *dom, unsigned int msg_seq, const void *data, unsigned int data_size );
int   kvmi_read_event_header( void *dom, unsigned int *id, unsigned int *size, unsigned int *seq );
int   kvmi_read_event_data( void *dom, void *buf, unsigned int size );
int   kvmi_read_event( void *dom, void *buf, unsigned int max_size, unsigned int *seq );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LIBKVMI_H_INCLUDED__ */

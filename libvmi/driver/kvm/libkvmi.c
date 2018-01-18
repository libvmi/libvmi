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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <poll.h>
#include <kvmi/libkvmi.h>
#include <linux/kvm_para.h>
#include <sys/stat.h>

#define MIN( X, Y ) ( ( X ) < ( Y ) ? ( X ) : ( Y ) )

/* VSOCK types and consts */
/* #include "kernel/uapi/linux/vm_sockets.h" */
typedef unsigned short __kernel_sa_family_t;
struct sockaddr_vm {
	__kernel_sa_family_t svm_family;
	unsigned short       svm_reserved1;
	unsigned int         svm_port;
	unsigned int         svm_cid;
	unsigned char        svm_zero[sizeof( struct sockaddr ) - sizeof( sa_family_t ) - sizeof( unsigned short ) -
                               sizeof( unsigned int ) - sizeof( unsigned int )];
};
#ifndef AF_VSOCK
#define AF_VSOCK 40 /* vSockets                 */
#define PF_VSOCK AF_VSOCK
#endif

#ifndef VMADDR_CID_ANY
#define VMADDR_CID_ANY -1U
#endif

struct kvmi_dom {
	int               fd;
	int               mem_fd;
	kvmi_new_event_cb event_cb;
	void *            cb_ctx;
};

struct kvmi_ctx {
	kvmi_new_guest_cb  accept_cb;
	kvmi_new_event_cb  event_cb;
	void *             cb_ctx;
	pthread_t          th_id;
	bool               th_started;
	int                th_fds[2];
	int                fd;
	struct sockaddr_un un_addr;
	struct sockaddr_vm v_addr;
};

static long pagesize;

__attribute__(( constructor )) static void lib_init()
{
	pagesize = sysconf( _SC_PAGE_SIZE );
}

static bool setup_socket( struct kvmi_ctx *ctx, struct sockaddr *sa, size_t sa_size, int pf )
{
	ctx->fd = socket( pf, SOCK_STREAM, 0 );

	if ( ctx->fd == -1 )
		return false;

	if ( bind( ctx->fd, sa, sa_size ) == -1 )
		return false;

	if ( listen( ctx->fd, 0 ) == -1 )
		return false;

	/* mark the file descriptor as close-on-execute */
	if ( fcntl( ctx->fd, F_SETFD, FD_CLOEXEC ) < 0 )
		return false;

	return true;
}

static bool setup_unix_socket( struct kvmi_ctx *ctx, const char *path )
{
	struct stat      st;
	bool             done;
	struct sockaddr *sa;

	if ( !path || path[0] == 0 )
		return false;

	if ( stat( path, &st ) == 0 && unlink( path ) ) /* Address already in use */
		return false;

	ctx->un_addr.sun_family = AF_UNIX;
	strncpy( ctx->un_addr.sun_path, path, sizeof( ctx->un_addr.sun_path ) );

	sa = ( struct sockaddr * )&ctx->un_addr;

	done = setup_socket( ctx, sa, sizeof( ctx->un_addr ), PF_UNIX );

	if ( done )
		done = !chmod( ctx->un_addr.sun_path, 0777 );

	return done;
}

static bool setup_vsock( struct kvmi_ctx *ctx, unsigned int port )
{
	struct sockaddr *sa;

	if ( !port )
		return false;

	ctx->v_addr.svm_family = AF_VSOCK;
	ctx->v_addr.svm_cid    = VMADDR_CID_ANY;
	ctx->v_addr.svm_port   = port;

	sa = ( struct sockaddr * )&ctx->v_addr;

	return setup_socket( ctx, sa, sizeof( ctx->v_addr ), PF_VSOCK );
}

static int do_read( int fd, void *buf, size_t size )
{
	errno = 0;

	for ( ;; ) {
		ssize_t n;

		do {
			n = recv( fd, buf, size, 0 );
		} while ( n < 0 && errno == EINTR );

		/* error or connection closed */
		if ( n <= 0 )
			return -1;

		buf = ( char * )buf + n;
		size -= n;
		if ( !size )
			break;
	}

	return 0;
}

static int do_write( int fd, const void *data, size_t size )
{
	ssize_t n;

	errno = 0;

	do {
		n = send( fd, data, size, MSG_NOSIGNAL );
	} while ( n < 0 && errno == EINTR );

	if ( n != ( ssize_t )size ) {
		errno = EIO;
		return -1;
	}

	return 0;
}

static bool handshake( struct kvmi_dom *dom, unsigned char ( *uuid )[16] )
{
	int       done = false;
	unsigned *blk;
	unsigned  sz;

	/*
	   Currently, we must read
	        struct {
	                unsigned sizeof_struct;
	                uuid char[16];
	        };
	   and write back the same structure.
	 */

	if ( do_read( dom->fd, &sz, 4 ) == -1 )
		return false;

	if ( sz < 4 + 16 || sz > 1 * 1024 * 1024 )
		return false;

	blk = malloc( sz );
	if ( !blk )
		return false;

	blk[0] = sz;

	if ( do_read( dom->fd, blk + 1, sz - 4 ) == 0 && do_write( dom->fd, blk, sz ) == 0 ) {
		unsigned version;

		memcpy( uuid, blk + 1, 16 );

		done = ( kvmi_get_version( dom, &version ) == 0 && version >= KVMI_VERSION );
	}

	free( blk );

	return done;
}

static void *accept_worker( void *_ctx )
{
	struct kvmi_ctx *ctx = _ctx;

	for ( ;; ) {
		struct kvmi_dom *dom;
		unsigned char    uuid[16];
		int              ret;
		int              fd;
		struct pollfd    fds[2];

		memset( fds, 0, sizeof( fds ) );

		fds[0].fd     = ctx->fd;
		fds[0].events = POLLIN;

		fds[1].fd     = ctx->th_fds[0];
		fds[1].events = POLLIN;

		do {
			ret = poll( fds, sizeof( fds ) / sizeof( fds[0] ), -1 );
		} while ( ret < 0 && errno == EINTR );

		if ( ret < 0 )
			break;

		if ( fds[1].revents )
			break;

		if ( !fds[0].revents )
			break;

		do {
			fd = accept( ctx->fd, NULL, NULL );
		} while ( fd < 0 && errno == EINTR );

		if ( fd == -1 )
			break;

		dom = calloc( 1, sizeof( *dom ) );
		if ( !dom )
			break;

		dom->fd = fd;
		if ( !handshake( dom, &uuid ) ) {
			kvmi_domain_close( dom );
			continue;
		}

		dom->mem_fd = open( "/dev/kvmmem", O_RDWR );

		dom->event_cb = ctx->event_cb;
		dom->cb_ctx   = ctx->cb_ctx;

		errno = 0;

		if ( ctx->accept_cb( dom, &uuid, ctx->cb_ctx ) != 0 ) {
			kvmi_domain_close( dom );
			break;
		}
	}

	return NULL;
}

static struct kvmi_ctx *alloc_kvmi_ctx( kvmi_new_guest_cb accept_cb, kvmi_new_event_cb event_cb, void *cb_ctx )
{
	struct kvmi_ctx *ctx;

	if ( !accept_cb )
		return NULL;

	ctx = calloc( 1, sizeof( *ctx ) );
	if ( !ctx )
		return NULL;

	ctx->fd = -1;

	ctx->accept_cb = accept_cb;
	ctx->event_cb  = event_cb;
	ctx->cb_ctx    = cb_ctx;

	ctx->th_fds[0] = -1;
	ctx->th_fds[1] = -1;

	/* these will be used to signal the accept worker to exit */
	if ( pipe( ctx->th_fds ) < 0 ) {
		free( ctx );
		return NULL;
	}

	return ctx;
}

static bool start_listener( struct kvmi_ctx *ctx )
{
	if ( pthread_create( &ctx->th_id, NULL, accept_worker, ctx ) )
		return false;

	ctx->th_started = true;
	return true;
}

void *kvmi_init_unix_socket( const char *socket, kvmi_new_guest_cb accept_cb, kvmi_new_event_cb event_cb, void *cb_ctx )
{
	struct kvmi_ctx *ctx;
	int              err;

	errno = 0;

	ctx = alloc_kvmi_ctx( accept_cb, event_cb, cb_ctx );
	if ( !ctx )
		return NULL;

	if ( !setup_unix_socket( ctx, socket ) )
		goto out_err;

	if ( !start_listener( ctx ) )
		goto out_err;

	return ctx;
out_err:
	err = errno;
	kvmi_uninit( ctx );
	errno = err;
	return NULL;
}

void *kvmi_init_vsock( unsigned int port, kvmi_new_guest_cb accept_cb, kvmi_new_event_cb event_cb, void *cb_ctx )
{
	struct kvmi_ctx *ctx;
	int              err;

	errno = 0;

	ctx = alloc_kvmi_ctx( accept_cb, event_cb, cb_ctx );
	if ( !ctx )
		return NULL;

	if ( !setup_vsock( ctx, port ) )
		goto out_err;

	if ( !start_listener( ctx ) )
		goto out_err;

	return ctx;
out_err:
	err = errno;
	kvmi_uninit( ctx );
	errno = err;
	return NULL;
}

void kvmi_uninit( void *_ctx )
{
	struct kvmi_ctx *ctx = _ctx;

	if ( !ctx )
		return;

	if ( ctx->fd != -1 ) {
		shutdown( ctx->fd, SHUT_RDWR );
		close( ctx->fd );
	}

	if ( ctx->th_fds[1] != -1 && ctx->th_started ) {
		/* we have a running thread */
		if ( write( ctx->th_fds[1], "\n", 1 ) == 1 )
			pthread_join( ctx->th_id, NULL );
	}

	/* close pipe between threads */
	if ( ctx->th_fds[0] != -1 )
		close( ctx->th_fds[0] );
	if ( ctx->th_fds[1] != -1 )
		close( ctx->th_fds[1] );

	free( ctx );
}

void kvmi_domain_close( void *d )
{
	struct kvmi_dom *dom = d;

	if ( dom ) {
		close( dom->fd );
		free( dom );
	}
}

int kvmi_connection_fd( void *d )
{
	struct kvmi_dom *dom = d;

	return dom->fd;
}

void kvmi_set_event_cb( void *d, kvmi_new_event_cb cb, void *cb_ctx )
{
	struct kvmi_dom *dom = d;

	dom->event_cb = cb;
	dom->cb_ctx   = cb_ctx;
}

/* The same sequence variable is used by all domains. */
static unsigned int new_seq( void )
{
	static unsigned int seq;

	return __sync_add_and_fetch( &seq, 1 );
}

/* We must send the whole request/reply with one write() call */
static int send_msg( int fd, unsigned short msg_id, unsigned msg_seq, const void *data, size_t data_size )
{
	size_t               size      = sizeof( struct kvmi_msg_hdr ) + data_size;
	unsigned char        buf[1024] = {};
	struct kvmi_msg_hdr *r         = ( struct kvmi_msg_hdr * )buf;
	int                  err;

	if ( size > sizeof( buf ) ) {
		r = malloc( size );

		if ( !r )
			return -1;
	}

	r->id   = msg_id;
	r->seq  = msg_seq;
	r->size = data_size;

	if ( data_size )
		memcpy( r + 1, data, data_size );

	err = do_write( fd, r, size );

	if ( r != ( struct kvmi_msg_hdr * )buf )
		free( r );

	return err;
}

static bool is_event( unsigned msg_id )
{
	return ( msg_id == KVMI_EVENT );
}

static int consume_bytes( int fd, unsigned size )
{
	while ( size ) {
		unsigned char buf[1024];
		unsigned      chunk = ( size < sizeof( buf ) ) ? size : sizeof( buf );

		if ( do_read( fd, buf, chunk ) )
			return -1;

		size -= chunk;
	}
	return 0;
}

static int read_event( struct kvmi_dom *dom, unsigned seq, unsigned size )
{
	if ( dom->event_cb ) {
		errno = 0;
		return dom->event_cb( dom, seq, size, dom->cb_ctx );
	}

	return consume_bytes( dom->fd, size );
}

static int recv_reply_header( struct kvmi_dom *dom, const struct kvmi_msg_hdr *req, unsigned *size )
{
	struct kvmi_msg_hdr h;

	while ( 0 == do_read( dom->fd, &h, sizeof( h ) ) ) {
		if ( is_event( h.id ) ) {
			if ( read_event( dom, h.seq, h.size ) )
				break;
		} else if ( h.id != req->id || h.seq != req->seq ) {
			errno = ENOMSG;
			break;
		} else {
			*size = h.size;
			return 0;
		}
	}

	return -1;
}

static int convert_kvm_error_to_errno( int err )
{
	switch ( err ) {
		case -KVM_ENOSYS:
			return ENOSYS;
		case -KVM_EFAULT:
			return EFAULT;
		case -KVM_E2BIG:
			return E2BIG;
		case -KVM_EPERM:
			return EPERM;
		case -KVM_EOPNOTSUPP:
			return EOPNOTSUPP;
		case -KVM_EAGAIN:
			return EAGAIN;
		case -KVM_EBUSY:
			return EBUSY;
		case -KVM_EINVAL:
			return EINVAL;
		case -KVM_ENOENT:
			return ENOENT;
		case -KVM_ENOMEM:
			return ENOMEM;
		default:
			return EPROTO;
	}
}

static int recv_error_code( int fd, unsigned *msg_size )
{
	struct kvmi_error_code ec;

	if ( *msg_size < sizeof( ec ) ) {
		errno = ENODATA;
		return -1;
	}

	if ( do_read( fd, &ec, sizeof( ec ) ) )
		return -1;

	if ( ec.err ) {
		errno = convert_kvm_error_to_errno( ec.err );
		return -1;
	}

	*msg_size -= sizeof( ec );
	return 0;
}

static int recv_reply( struct kvmi_dom *dom, const struct kvmi_msg_hdr *req, void *dest, size_t dest_size )
{
	unsigned size = 0;

	if ( recv_reply_header( dom, req, &size ) )
		return -1;

	if ( recv_error_code( dom->fd, &size ) )
		return -1;

	if ( size > dest_size ) {
		errno = E2BIG;
		return -1;
	}

	if ( size != dest_size ) {
		errno = ENODATA;
		return -1;
	}

	if ( !dest_size )
		return 0;

	return do_read( dom->fd, dest, dest_size );
}

static int request( struct kvmi_dom *dom, unsigned short msg_id, const void *src, size_t src_size, void *dest,
                    size_t dest_size )
{
	struct kvmi_msg_hdr req = { .id = msg_id, .seq = new_seq() };

	if ( send_msg( dom->fd, msg_id, req.seq, src, src_size ) )
		return -1;

	return recv_reply( dom, &req, dest, dest_size );
}

int kvmi_control_events( void *dom, unsigned short vcpu, unsigned int events )
{
	struct kvmi_control_events req = { .vcpu = vcpu, .events = events };

	return request( dom, KVMI_CONTROL_EVENTS, &req, sizeof( req ), NULL, 0 );
}

int kvmi_control_cr( void *dom, unsigned int cr, bool enable )
{
	struct kvmi_control_cr req = { .vcpu = 0, .cr = cr, .enable = enable };

	return request( dom, KVMI_CONTROL_CR, &req, sizeof( req ), NULL, 0 );
}

int kvmi_control_msr( void *dom, unsigned int msr, bool enable )
{
	struct kvmi_control_msr req = { .vcpu = 0, .msr = msr, .enable = enable };

	return request( dom, KVMI_CONTROL_MSR, &req, sizeof( req ), NULL, 0 );
}

int kvmi_get_page_access( void *dom, unsigned short vcpu, unsigned long long int gpa, unsigned char *access )
{
	struct kvmi_get_page_access *      req      = NULL;
	struct kvmi_get_page_access_reply *rpl      = NULL;
	size_t                             req_size = sizeof( *req ) + 1 * sizeof( req->gpa[0] );
	size_t                             rpl_size = sizeof( *rpl ) + 1 * sizeof( rpl->access[0] );
	int                                err      = -1;

	req = malloc( req_size );
	rpl = malloc( rpl_size );
	if ( !req || !rpl )
		goto out;

	memset( req, 0, req_size );
	req->vcpu   = vcpu;
	req->count  = 1;
	req->gpa[0] = gpa;

	err = request( dom, KVMI_GET_PAGE_ACCESS, req, req_size, rpl, rpl_size );

	if ( !err )
		*access = rpl->access[0];

out:
	free( req );
	free( rpl );

	return err;
}

int kvmi_set_page_access( void *dom, unsigned short vcpu, unsigned long long int *gpa, unsigned char *access,
                          unsigned short count )
{
	struct kvmi_set_page_access *req;
	size_t                       req_size = sizeof( *req ) + count * sizeof( req->entries[0] );
	int                          err      = -1, k;

	req = malloc( req_size );
	if ( !req )
		return -1;

	memset( req, 0, req_size );
	req->vcpu  = vcpu;
	req->count = count;

	for ( k = 0; k < count; k++ ) {
		req->entries[k].gpa    = gpa[k];
		req->entries[k].access = access[k];
	}

	err = request( dom, KVMI_SET_PAGE_ACCESS, req, req_size, NULL, 0 );

	free( req );

	return err;
}

int kvmi_get_vcpu_count( void *dom, unsigned short *count )
{
	struct kvmi_get_guest_info       req = { .vcpu = 0 };
	struct kvmi_get_guest_info_reply rpl;
	int                              err;

	err = request( dom, KVMI_GET_GUEST_INFO, &req, sizeof( req ), &rpl, sizeof( rpl ) );

	if ( !err )
		*count = rpl.vcpu_count;

	return err;
}

int kvmi_get_tsc_speed( void *dom, unsigned long long int *speed )
{
	struct kvmi_get_guest_info       req = { .vcpu = 0 };
	struct kvmi_get_guest_info_reply rpl;
	int                              err;

	err = request( dom, KVMI_GET_GUEST_INFO, &req, sizeof( req ), &rpl, sizeof( rpl ) );

	if ( !err )
		*speed = rpl.tsc_speed;

	return err;
}

int kvmi_get_cpuid( void *dom, unsigned short vcpu, unsigned int function, unsigned int index, unsigned int *eax,
                    unsigned int *ebx, unsigned int *ecx, unsigned int *edx )
{
	int                         err;
	struct kvmi_get_cpuid_reply rpl;
	struct kvmi_get_cpuid       req = { .vcpu = vcpu, .function = function, .index = index };

	err = request( dom, KVMI_GET_CPUID, &req, sizeof( req ), &rpl, sizeof( rpl ) );

	if ( !err ) {
		*eax = rpl.eax;
		*ebx = rpl.ebx;
		*ecx = rpl.ecx;
		*edx = rpl.edx;
	}

	return err;
}

static int request_varlen_response( void *d, unsigned short msg_id, const void *src, size_t src_size,
                                    unsigned int *rpl_size )
{
	struct kvmi_msg_hdr req = { .id = msg_id, .seq = new_seq() };
	struct kvmi_dom *   dom = d;

	if ( send_msg( dom->fd, msg_id, req.seq, src, src_size ) )
		return -1;

	if ( recv_reply_header( dom, &req, rpl_size ) )
		return -1;

	if ( recv_error_code( dom->fd, rpl_size ) )
		return -1;

	return 0;
}

int kvmi_get_xsave( void *d, unsigned short vcpu, void *buffer, size_t buf_size )
{
	struct kvmi_get_xsave req = { .vcpu = vcpu };
	unsigned int          received;
	int                   err = -1;
	struct kvmi_dom *     dom = d;

	if ( request_varlen_response( dom, KVMI_GET_XSAVE, &req, sizeof( req ), &received ) )
		goto out;

	if ( do_read( dom->fd, buffer, MIN( buf_size, received ) ) )
		goto out;

	if ( received > buf_size )
		consume_bytes( dom->fd, received - buf_size );
	else
		memset( buffer + received, 0, buf_size - received );

	err = 0;
out:

	return err;
}

int kvmi_inject_page_fault( void *dom, unsigned short vcpu, unsigned long long int gva, unsigned int error )
{
	struct kvmi_inject_exception req = {
		.vcpu = vcpu, .nr = PF_VECTOR, .has_error = true, .error_code = error, .address = gva
	};

	return request( dom, KVMI_INJECT_EXCEPTION, &req, sizeof( req ), NULL, 0 );
}

int kvmi_read_physical( void *dom, unsigned long long int gpa, void *buffer, size_t size )
{
	struct kvmi_read_physical req = { .gpa = gpa, .size = size };

	return request( dom, KVMI_READ_PHYSICAL, &req, sizeof( req ), buffer, size );
}

int kvmi_write_physical( void *dom, unsigned long long int gpa, const void *buffer, size_t size )
{
	struct kvmi_write_physical *req;
	size_t                      req_size = sizeof( *req ) + size;
	int                         err      = -1;

	req = malloc( req_size );
	if ( !req )
		return -1;

	req->gpa  = gpa;
	req->size = size;
	memcpy( req->data, buffer, size );

	err = request( dom, KVMI_WRITE_PHYSICAL, req, req_size, NULL, 0 );

	free( req );

	return err;
}

void *kvmi_map_physical_page( void *d, unsigned long long int gpa )
{
	struct kvmi_dom *dom = d;

	errno = 0;

	void *addr = mmap( NULL, pagesize, PROT_READ | PROT_WRITE,
	                   MAP_LOCKED | MAP_POPULATE | MAP_SHARED | MAP_ANONYMOUS, -1, 0 );

	if ( addr != MAP_FAILED ) {
		struct kvmi_get_map_token_reply req;
		struct kvmi_mem_map             map_req;
		int                             err;

		err = request( dom, KVMI_GET_MAP_TOKEN, NULL, 0, &req, sizeof( req ) );

		if ( !err ) {
			/* fill IOCTL arg */
			memcpy( &map_req.token, &req.token, sizeof( struct kvmi_map_mem_token ) );
			map_req.gpa = gpa;
			map_req.gva = ( __u64 )addr;

			/* do map IOCTL request */
			err = ioctl( dom->mem_fd, KVM_INTRO_MEM_MAP, &map_req );
		}

		if ( err ) {
			int _errno = errno;
			munmap( addr, pagesize );
			errno = _errno;
			addr  = MAP_FAILED;
		}
	}

	return addr;
}

int kvmi_unmap_physical_page( void *d, void *addr )
{
	struct kvmi_dom *dom = d;
	int              _errno;
	int              err;

	/* do unmap IOCTL request */
	err    = ioctl( dom->mem_fd, KVM_INTRO_MEM_UNMAP, addr );
	_errno = errno;

	munmap( addr, pagesize );

	errno = _errno;

	return err;
}

static void *alloc_get_registers_req( unsigned short vcpu, struct kvm_msrs *msrs, size_t *req_size )
{
	struct kvmi_get_registers *req;

	*req_size = sizeof( struct kvmi_get_registers ) + sizeof( __u32 ) * msrs->nmsrs;
	req       = malloc( *req_size );

	if ( req ) {
		unsigned k = 0;

		memset( req, 0, *req_size );
		req->vcpu  = vcpu;
		req->nmsrs = msrs->nmsrs;

		for ( ; k < msrs->nmsrs; k++ )
			req->msrs_idx[k] = msrs->entries[k].index;
	}

	return req;
}

static int process_get_registers_reply( int fd, size_t received, struct kvm_regs *regs, struct kvm_sregs *sregs,
                                        struct kvm_msrs *msrs, unsigned int *mode )
{
	struct kvmi_get_registers_reply rpl;

	if ( received != sizeof( rpl ) + sizeof( struct kvm_msr_entry ) * msrs->nmsrs ) {
		errno = E2BIG;
		return -1;
	}

	if ( do_read( fd, &rpl, sizeof( rpl ) ) )
		return -1;

	if ( do_read( fd, &msrs->entries, sizeof( struct kvm_msr_entry ) * msrs->nmsrs ) )
		return -1;

	memcpy( regs, &rpl.regs, sizeof( *regs ) );
	memcpy( sregs, &rpl.sregs, sizeof( *sregs ) );
	*mode = rpl.mode;

	return 0;
}

int kvmi_get_registers( void *d, unsigned short vcpu, struct kvm_regs *regs, struct kvm_sregs *sregs,
                        struct kvm_msrs *msrs, unsigned int *mode )
{
	struct kvmi_dom *          dom = d;
	struct kvmi_get_registers *req;
	size_t                     req_size;
	int                        err = -1;
	unsigned int               received;

	req = alloc_get_registers_req( vcpu, msrs, &req_size );

	if ( !req )
		return -1;

	err = request_varlen_response( dom, KVMI_GET_REGISTERS, req, req_size, &received );

	if ( !err )
		err = process_get_registers_reply( dom->fd, received, regs, sregs, msrs, mode );

	free( req );
	return err;
}

int kvmi_set_registers( void *dom, unsigned short vcpu, const struct kvm_regs *regs )
{
	struct kvmi_set_registers req = { .vcpu = vcpu, .regs = *regs };

	return request( dom, KVMI_SET_REGISTERS, &req, sizeof( req ), NULL, 0 );
}

int kvmi_read_event_header( void *d, unsigned int *id, unsigned int *size, unsigned int *seq )
{
	struct kvmi_dom *   dom = d;
	struct kvmi_msg_hdr h;

	if ( do_read( dom->fd, &h, sizeof( h ) ) )
		return -1;

	*id   = h.id;
	*seq  = h.seq;
	*size = h.size;

	return 0;
}

int kvmi_read_event_data( void *d, void *buf, unsigned int size )
{
	struct kvmi_dom *dom = d;

	return do_read( dom->fd, buf, size );
}

/* We must send the whole reply with one send/write() call */
int kvmi_reply_event( void *d, unsigned int msg_seq, const void *data, unsigned int data_size )
{
	struct kvmi_dom *dom = d;

	return send_msg( dom->fd, KVMI_EVENT_REPLY, msg_seq, data, data_size );
}

int kvmi_get_version( void *dom, unsigned int *version )
{
	struct kvmi_get_version_reply rpl;
	int                           err;

	err = request( dom, KVMI_GET_VERSION, NULL, 0, &rpl, sizeof( rpl ) );
	if ( !err )
		*version = rpl.version;

	return err;
}

int kvmi_read_event( void *dom, void *buf, unsigned int max_size, unsigned int *seq )
{
	unsigned int msgid;
	unsigned int msgsize;

	if ( kvmi_read_event_header( dom, &msgid, &msgsize, seq ) )
		return -1;

	if ( msgid != KVMI_EVENT || msgsize > max_size ) {
		errno = EINVAL;
		return -1;
	}

	return kvmi_read_event_data( dom, buf, msgsize );
}

int kvmi_pause_vcpu( void *dom, unsigned short vcpu )
{
	struct kvmi_pause_vcpu req = { .vcpu = vcpu };

	return request( dom, KVMI_PAUSE_VCPU, &req, sizeof( req ), NULL, 0 );
}

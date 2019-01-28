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
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <poll.h>
#include <kvmi/libkvmi.h>
#include <linux/kvm_para.h>
#include <sys/stat.h>
#include <stdarg.h>

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

#define MAX_QUEUED_EVENTS 16384 /* 16KiB */

struct kvmi_dom {
	int                           fd;
	bool                          disconnected;
	int                           mem_fd;
	void *                        cb_ctx;
	struct kvmi_dom_event         *events;
	struct kvmi_dom_event         *event_last;
	unsigned int                  event_count;
	pthread_mutex_t               event_lock;
	pthread_mutex_t               lock;
	struct kvmi_qemu2introspector hsk;
};

struct kvmi_ctx {
	kvmi_new_guest_cb  accept_cb;
	kvmi_handshake_cb  handshake_cb;
	void *             cb_ctx;
	pthread_t          th_id;
	bool               th_started;
	int                th_fds[2];
	int                fd;
	struct sockaddr_un un_addr;
	struct sockaddr_vm v_addr;
};

static long        pagesize;
static kvmi_log_cb log_cb;
static void *      log_ctx;

__attribute__( ( constructor ) ) static void lib_init( void )
{
	pagesize = sysconf( _SC_PAGE_SIZE );
}

static void kvmi_log_generic( kvmi_log_level level, const char *s, va_list va )
{
	char *buf = NULL;

	if ( !log_cb )
		return;

	if ( vasprintf( &buf, s, va ) < 0 )
		return;

	log_cb( level, buf, log_ctx );

	free( buf );
}

static void kvmi_log_error( const char *s, ... )
{
	va_list va;

	va_start( va, s );
	kvmi_log_generic( KVMI_LOG_LEVEL_ERROR, s, va );
	va_end( va );
}

static void kvmi_log_warning( const char *s, ... )
{
	va_list va;

	va_start( va, s );
	kvmi_log_generic( KVMI_LOG_LEVEL_WARNING, s, va );
	va_end( va );
}

static bool setup_socket( struct kvmi_ctx *ctx, const struct sockaddr *sa, size_t sa_size, int pf )
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

bool kvmi_domain_is_connected( const void *d )
{
	const struct kvmi_dom *dom = d;

	return !dom->disconnected;
}

static void check_if_disconnected( struct kvmi_dom *dom, int err )
{
	if ( dom->disconnected )
		return;

	dom->disconnected = ( err == ENOTCONN || err == EPIPE );
}

#define DEFAULT_WAIT_TIMEOUT 15000 /* 15s */

static int do_wait( struct kvmi_dom *dom, bool write )
{
	short         event = write ? POLLOUT : POLLIN;
	int           err;
	struct pollfd pfd[1] = {};

	pfd[0].fd     = dom->fd;
	pfd[0].events = event;

	do {
		err = poll( pfd, 1, DEFAULT_WAIT_TIMEOUT );
	} while ( err < 0 && errno == EINTR );

	if ( err )
		check_if_disconnected( dom, errno );
	else {
		errno = ETIMEDOUT;
		return -1;
	}

	if ( pfd[0].revents & event )
		return 0;

	return -1;
}

static int do_read( struct kvmi_dom *dom, void *buf, size_t size )
{
	errno = 0;

	for ( ;; ) {
		ssize_t n;

		if ( do_wait( dom, false ) < 0 )
			return -1;

		do {
			n = recv( dom->fd, buf, size, 0 );
		} while ( n < 0 && errno == EINTR );

		if ( !n ) {
			errno = ENOTCONN;
			dom->disconnected = true;
			return -1;
		}

		if ( n < 0 ) {
			if ( errno == EAGAIN || errno == EWOULDBLOCK )
				/* go wait for the socket to become available again */
				continue;
			check_if_disconnected( dom, errno );
			return -1;
		}

		buf = ( char * )buf + n;
		size -= n;
		if ( !size )
			break;
	}

	return 0;
}

static int do_write( struct kvmi_dom *dom, const void *buf, size_t size )
{
	errno = 0;

	for ( ;; ) {
		ssize_t n;

		if ( do_wait( dom, true ) < 0 )
			return -1;

		do {
			n = send( dom->fd, buf, size, MSG_NOSIGNAL );
		} while ( n < 0 && errno == EINTR );

		if ( n < 0 ) {
			if ( errno == EAGAIN || errno == EWOULDBLOCK )
				/* go wait for the socket to become available again */
				continue;
			check_if_disconnected( dom, errno );
			return -1;
		}

		buf = ( char * )buf + n;
		size -= n;
		if ( !size )
			break;
	}

	return 0;
}

static bool unsupported_version( struct kvmi_dom *dom )
{
	unsigned int version;

	if ( kvmi_get_version( dom, &version ) ) {
		kvmi_log_error( "failed to retrieve the protocol version (invalid authentication token?)" );
		return true;
	}

	if ( version < KVMI_VERSION ) {
		kvmi_log_error( "invalid protocol version (received 0x%08x, expected at least 0x%08x)", version,
		                KVMI_VERSION );
		return true;
	}

	return false;
}

static bool handshake_done( struct kvmi_ctx *ctx, struct kvmi_dom *dom )
{
	struct kvmi_qemu2introspector *qemu = &dom->hsk;
	struct kvmi_introspector2qemu  intro;
	uint32_t                       sz;
	char *                         ptr;

	if ( do_read( dom, &sz, sizeof( sz ) ) )
		return false;

	if ( sz > 1 * 1024 * 1024 || sz < sizeof( qemu->struct_size ) )
		return false;

	qemu->struct_size = MIN( sz, sizeof( *qemu ) );
	ptr               = ( char * )&qemu->struct_size + sizeof( qemu->struct_size );
	sz                = qemu->struct_size - sizeof( qemu->struct_size );

	if ( do_read( dom, ptr, sz ) )
		return false;

	qemu->name[sizeof( qemu->name ) - 1] = 0;

	memset( &intro, 0, sizeof( intro ) );
	intro.struct_size = sizeof( intro );
	if ( ctx->handshake_cb && ctx->handshake_cb( qemu, &intro, ctx->cb_ctx ) )
		return false;

	return do_write( dom, &intro, sizeof( intro ) ) == 0;
}

static int set_nonblock( int fd )
{
	int flags = fcntl( fd, F_GETFL );

	if ( flags == -1 )
		return -1;

	if ( fcntl( fd, F_SETFL, flags | O_NONBLOCK ) == -1 )
		return -1;

	return 0;
}

static void *accept_worker( void *_ctx )
{
	struct kvmi_ctx *ctx = _ctx;

	for ( ;; ) {
		struct kvmi_dom *dom;
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

		if ( set_nonblock( fd ) ) {
			shutdown( fd, SHUT_RDWR );
			close( fd );
			break;
		}

		dom = calloc( 1, sizeof( *dom ) );
		if ( !dom )
			break;

		dom->fd     = fd;
		dom->mem_fd = -1;
		pthread_mutex_init( &dom->event_lock, NULL );
		pthread_mutex_init( &dom->lock, NULL );

		if ( !handshake_done( ctx, dom ) ) {
			kvmi_log_error( "the handshake has failed" );
			kvmi_domain_close( dom, true );
			continue;
		}

		if ( unsupported_version( dom ) ) {
			kvmi_domain_close( dom, true );
			continue;
		}

		dom->mem_fd = open( "/dev/kvmmem", O_RDWR );
		if ( dom->mem_fd < 0 )
			kvmi_log_warning( "memory mapping not supported" );

		dom->cb_ctx = ctx->cb_ctx;

		if ( ctx->accept_cb( dom, &dom->hsk.uuid, ctx->cb_ctx ) != 0 ) {
			kvmi_domain_close( dom, true );
			continue;
		}
	}

	return NULL;
}

static struct kvmi_ctx *alloc_kvmi_ctx( kvmi_new_guest_cb accept_cb, kvmi_handshake_cb hsk_cb, void *cb_ctx )
{
	struct kvmi_ctx *ctx;

	if ( !accept_cb )
		return NULL;

	ctx = calloc( 1, sizeof( *ctx ) );
	if ( !ctx )
		return NULL;

	ctx->fd = -1;

	ctx->accept_cb    = accept_cb;
	ctx->handshake_cb = hsk_cb;
	ctx->cb_ctx       = cb_ctx;

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

void *kvmi_init_unix_socket( const char *socket, kvmi_new_guest_cb accept_cb, kvmi_handshake_cb hsk_cb, void *cb_ctx )
{
	struct kvmi_ctx *ctx;
	int              err;

	errno = 0;

	ctx = alloc_kvmi_ctx( accept_cb, hsk_cb, cb_ctx );
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

void *kvmi_init_vsock( unsigned int port, kvmi_new_guest_cb accept_cb, kvmi_handshake_cb hsk_cb, void *cb_ctx )
{
	struct kvmi_ctx *ctx;
	int              err;

	errno = 0;

	ctx = alloc_kvmi_ctx( accept_cb, hsk_cb, cb_ctx );
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

/*
 * This function is called by the child of a process that did kvm_init().
 * All this does is close the file descriptor so that there's no longer
 * a reference to it. The threads cannot be uninitialized because after
 * fork they are in an undefined state (it's unspecified if they can be
 * joined).
 */
void kvmi_close( void *_ctx )
{
	struct kvmi_ctx *ctx = _ctx;

	if ( !ctx )
		return;

	if ( ctx->fd != -1 ) {
		close( ctx->fd );
		ctx->fd = -1;
	}
}

void kvmi_domain_close( void *d, bool do_shutdown )
{
	struct kvmi_dom *dom = d;

	if ( !dom )
		return;

	if ( dom->mem_fd != -1 )
		close( dom->mem_fd );
	if ( do_shutdown )
		shutdown( dom->fd, SHUT_RDWR );
	close( dom->fd );

	for ( struct kvmi_dom_event *ev = dom->events; ev; ) {
		struct kvmi_dom_event *next = ev->next;

		free( ev );
		ev = next;
	}

	pthread_mutex_destroy( &dom->event_lock );

	pthread_mutex_destroy( &dom->lock );

	free( dom );
}

int kvmi_connection_fd( const void *d )
{
	const struct kvmi_dom *dom = d;

	return dom->fd;
}

void kvmi_domain_name( const void *d, char *buffer, size_t buffer_size )
{
	const struct kvmi_dom *dom = d;

	snprintf( buffer, buffer_size, "%s", dom->hsk.name );
}

int64_t kvmi_get_starttime( const void *d )
{
	const struct kvmi_dom *dom = d;

	return dom->hsk.start_time;
}

/* The same sequence variable is used by all domains. */
static unsigned int new_seq( void )
{
	static unsigned int seq;

	return __sync_add_and_fetch( &seq, 1 );
}

/* We must send the whole request/reply with one write() call */
static int send_msg( struct kvmi_dom *dom, unsigned short msg_id, unsigned msg_seq, const void *data, size_t data_size )
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

	err = do_write( dom, r, size );

	if ( r != ( struct kvmi_msg_hdr * )buf )
		free( r );

	return err;
}

static bool is_event( unsigned msg_id )
{
	return ( msg_id == KVMI_EVENT );
}

static int consume_bytes( struct kvmi_dom *dom, unsigned size )
{
	while ( size ) {
		unsigned char buf[1024];
		unsigned      chunk = ( size < sizeof( buf ) ) ? size : sizeof( buf );

		if ( do_read( dom, buf, chunk ) )
			return -1;

		size -= chunk;
	}
	return 0;
}

static int kvmi_read_event_data( void *d, void *buf, unsigned int size )
{
	struct kvmi_dom *dom = d;

	return do_read( dom, buf, size );
}

static int kvmi_push_event( struct kvmi_dom *dom, unsigned int seq, unsigned int size )
{
	bool                   queued = true;
	struct kvmi_dom_event *new_event;

	if ( size > FIELD_SIZEOF( struct kvmi_dom_event, event ) ) {
		errno = EINVAL;
		return -1;
	}

	new_event = calloc( 1, sizeof( *new_event ) );
	if ( !new_event )
		return -1;

	if ( kvmi_read_event_data( dom, &new_event->event, size ) ) {
		int _errno = errno;

		free( new_event );
		errno = _errno;
		return -1;
	}

	new_event->seq  = seq;
	new_event->next = NULL;

	pthread_mutex_lock( &dom->event_lock );
	/* Don't queue events ad infinitum */
	if ( dom->event_count < MAX_QUEUED_EVENTS ) {
		if ( dom->event_last )
			dom->event_last->next = new_event;
		else
			dom->events = new_event;
		dom->event_last = new_event;
		dom->event_count++;
	} else
		queued = false;
	pthread_mutex_unlock( &dom->event_lock );

	if ( !queued ) {
		free( new_event );
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

/* The caller is responsible for free()-ing the event */
int kvmi_pop_event( void *d, struct kvmi_dom_event **event )
{
	struct kvmi_dom *dom = d;

	pthread_mutex_lock( &dom->event_lock );
	*event = dom->events;
	if ( *event ) {
		dom->events = (*event)->next;

		if ( --dom->event_count == 0 )
			dom->event_last = NULL;

		(*event)->next = NULL;
	}
	pthread_mutex_unlock( &dom->event_lock );

	if ( *event == NULL ) {
		errno = EAGAIN;
		return -1;
	}

	return 0;
}

static int recv_reply_header( struct kvmi_dom *dom, const struct kvmi_msg_hdr *req, unsigned *size )
{
	struct kvmi_msg_hdr h;

	while ( !do_read( dom, &h, sizeof( h ) ) ) {
		if ( is_event( h.id ) ) {
			if ( kvmi_push_event( dom, h.seq, h.size ) )
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

static int recv_error_code( struct kvmi_dom *dom, unsigned *msg_size )
{
	struct kvmi_error_code ec;

	if ( *msg_size < sizeof( ec ) ) {
		errno = ENODATA;
		return -1;
	}

	if ( do_read( dom, &ec, sizeof( ec ) ) )
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

	if ( recv_error_code( dom, &size ) )
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

	return do_read( dom, dest, dest_size );
}

static int request( struct kvmi_dom *dom, unsigned short msg_id, const void *src, size_t src_size, void *dest,
                    size_t dest_size )
{
	int                 err;
	struct kvmi_msg_hdr req = { .id = msg_id, .seq = new_seq() };

	pthread_mutex_lock( &dom->lock );

	err = send_msg( dom, msg_id, req.seq, src, src_size );

	if ( !err )
		err = recv_reply( dom, &req, dest, dest_size );

	pthread_mutex_unlock( &dom->lock );

	return err;
}

int kvmi_control_events( void *dom, unsigned short vcpu, unsigned int events )
{
	struct kvmi_control_events req = { .vcpu = vcpu, .events = events };

	return request( dom, KVMI_CONTROL_EVENTS, &req, sizeof( req ), NULL, 0 );
}

int kvmi_control_cr( void *dom, unsigned short vcpu, unsigned int cr, bool enable )
{
	struct kvmi_control_cr req = { .vcpu = vcpu, .cr = cr, .enable = enable };

	return request( dom, KVMI_CONTROL_CR, &req, sizeof( req ), NULL, 0 );
}

int kvmi_control_msr( void *dom, unsigned short vcpu, unsigned int msr, bool enable )
{
	struct kvmi_control_msr req = { .vcpu = vcpu, .msr = msr, .enable = enable };

	return request( dom, KVMI_CONTROL_MSR, &req, sizeof( req ), NULL, 0 );
}

int kvmi_pause_all_vcpus( void *dom, unsigned int *count )
{
	struct kvmi_pause_all_vcpus_reply rpl;
	int                               err;

	err = request( dom, KVMI_PAUSE_ALL_VCPUS, NULL, 0, &rpl, sizeof( rpl ) );

	if ( !err )
		*count = rpl.vcpu_count;

	return err;
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

int kvmi_get_vcpu_count( void *dom, unsigned int *count )
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

	if ( send_msg( dom, msg_id, req.seq, src, src_size ) )
		return -1;

	if ( recv_reply_header( dom, &req, rpl_size ) )
		return -1;

	if ( recv_error_code( dom, rpl_size ) )
		return -1;

	return 0;
}

int kvmi_get_xsave( void *d, unsigned short vcpu, void *buffer, size_t buf_size )
{
	struct kvmi_get_xsave req = { .vcpu = vcpu };
	unsigned int          received;
	int                   err = -1;
	struct kvmi_dom *     dom = d;

	pthread_mutex_lock( &dom->lock );

	if ( request_varlen_response( dom, KVMI_GET_XSAVE, &req, sizeof( req ), &received ) )
		goto out;

	if ( do_read( dom, buffer, MIN( buf_size, received ) ) )
		goto out;

	if ( received > buf_size )
		consume_bytes( dom, received - buf_size );
	else
		memset( ( char * )buffer + received, 0, buf_size - received );

	err = 0;
out:

	pthread_mutex_unlock( &dom->lock );

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
		int                             retries = 0;
		int                             err;

		do {
			err = request( dom, KVMI_GET_MAP_TOKEN, NULL, 0, &req, sizeof( req ) );

			if ( !err ) {
				/* fill IOCTL arg */
				memcpy( &map_req.token, &req.token, sizeof( struct kvmi_map_mem_token ) );
				map_req.gpa = gpa;
				map_req.gva = ( __u64 )addr;

				/* do map IOCTL request */
				err = ioctl( dom->mem_fd, KVM_INTRO_MEM_MAP, &map_req );
			}

			if ( err && ( errno == EAGAIN || errno == EBUSY ) ) {
				retries++;
				if ( retries < 3 )
					sleep( 1 );
			} else
				break;
		} while ( retries < 3 );

		if ( err ) {
			int _errno = errno;
			munmap( addr, pagesize );
			errno = _errno;
			addr  = MAP_FAILED;
		}
	}

	return addr;
}

int kvmi_unmap_physical_page( const void *d, void *addr )
{
	const struct kvmi_dom *dom = d;
	int                    _errno;
	int                    err;

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

static int process_get_registers_reply( struct kvmi_dom *dom, size_t received, struct kvm_regs *regs,
                                        struct kvm_sregs *sregs, struct kvm_msrs *msrs, unsigned int *mode )
{
	struct kvmi_get_registers_reply rpl;

	if ( received != sizeof( rpl ) + sizeof( struct kvm_msr_entry ) * msrs->nmsrs ) {
		errno = E2BIG;
		return -1;
	}

	if ( do_read( dom, &rpl, sizeof( rpl ) ) )
		return -1;

	if ( do_read( dom, &msrs->entries, sizeof( struct kvm_msr_entry ) * msrs->nmsrs ) )
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

	pthread_mutex_lock( &dom->lock );

	err = request_varlen_response( dom, KVMI_GET_REGISTERS, req, req_size, &received );

	if ( !err )
		err = process_get_registers_reply( dom, received, regs, sregs, msrs, mode );

	pthread_mutex_unlock( &dom->lock );

	free( req );

	return err;
}

int kvmi_set_registers( void *dom, unsigned short vcpu, const struct kvm_regs *regs )
{
	struct kvmi_set_registers req = { .vcpu = vcpu, .regs = *regs };

	return request( dom, KVMI_SET_REGISTERS, &req, sizeof( req ), NULL, 0 );
}

/* We must send the whole reply with one send/write() call */
int kvmi_reply_event( void *d, unsigned int msg_seq, const void *data, unsigned int data_size )
{
	int              ret;
	struct kvmi_dom *dom = d;

	pthread_mutex_lock( &dom->lock );

	ret = send_msg( dom, KVMI_EVENT_REPLY, msg_seq, data, data_size );

	pthread_mutex_unlock( &dom->lock );

	return ret;
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

int kvmi_control_vm_events( void *dom, unsigned int events )
{
	struct kvmi_control_vm_events req = { .events = events };

	return request( dom, KVMI_CONTROL_VM_EVENTS, &req, sizeof( req ), NULL, 0 );
}

static int kvmi_read_event_header( struct kvmi_dom *dom, unsigned int *id, unsigned int *size, unsigned int *seq )
{
	struct kvmi_msg_hdr h;

	if ( do_read( dom, &h, sizeof( h ) ) )
		return -1;

	*id   = h.id;
	*seq  = h.seq;
	*size = h.size;

	return 0;
}

static int kvmi_read_event( struct kvmi_dom *dom )
{
	unsigned int msgid;
	unsigned int msgsize;
	unsigned int msgseq;

	if ( kvmi_read_event_header( dom, &msgid, &msgsize, &msgseq ) )
		return -1;

	if ( !is_event( msgid ) ) {
		errno = EINVAL;
		return -1;
	}

	return kvmi_push_event( dom, msgseq, msgsize );
}

static int wait_for_data( struct kvmi_dom *dom, int ms )
{
	struct pollfd fds = { .fd = dom->fd, .events = POLLIN };
	int           err;

	do {
		err = poll( &fds, 1, ms );
	} while ( err < 0 && errno == EINTR );

	if ( !err ) {
		/*
		 * The man page does not specify if poll() sets errno to
		 * ETIMEDOUT before returning 0
		 */
		errno = ETIMEDOUT;
		return -1;
	}

	if ( err < 0 )
		return err;

	if ( fds.revents & POLLHUP ) {
		errno = EPIPE;
		return err;
	}

	return 0;
}

int kvmi_wait_event( void *d, int ms )
{
	bool             empty;
	int              err;
	struct kvmi_dom *dom = d;

	/* Don't go waiting for events if one is already queued */
	pthread_mutex_lock( &dom->event_lock );
	empty = dom->events == NULL;
	pthread_mutex_unlock( &dom->event_lock );

	if ( !empty )
		return 0;

	err = wait_for_data( dom, ms );

	if ( !err ) {
		pthread_mutex_lock( &dom->lock );
		/* maybe the event was queued */
		err = wait_for_data( dom, 0 );
		if ( !err )
			err = kvmi_read_event( dom );
		pthread_mutex_unlock( &dom->lock );
	}

	return err;
}

void kvmi_set_log_cb( kvmi_log_cb cb, void *ctx )
{
	log_cb  = cb;
	log_ctx = ctx;
}

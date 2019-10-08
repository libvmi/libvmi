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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

#define MAX_QUEUED_EVENTS 16384
#define MAX_BATCH_IOVS 1001
#define MIN_KVMI_VERSION 1
#define MIN_HANDSHAKE_DATA offsetof( struct kvmi_qemu2introspector, name )
#define MAX_HANDSHAKE_DATA ( 64 * 1024 )
#define MAX_MAP_RETRIES 30
#define MAP_RETRY_WARNING 3
#define MAP_RETRY_SLEEP_SECS 1

#define KVMI_MAX_TIMEOUT 15000

struct kvmi_dom {
	int                           fd;
	unsigned int                  api_version;
	bool                          disconnected;
	int                           mem_fd;
	void *                        cb_ctx;
	struct kvmi_dom_event *       events;
	struct kvmi_dom_event *       event_last;
	unsigned int                  event_count;
	pthread_mutex_t               event_lock;
	pthread_mutex_t               lock;
	struct kvmi_qemu2introspector hsk;

	char     buff[5 * KVMI_MSG_SIZE];
	unsigned head;
	unsigned tail;
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

struct kvmi_control_cmd_response_msg {
	struct kvmi_msg_hdr              hdr;
	struct kvmi_control_cmd_response cmd;
};

struct kvmi_batch {
	struct kvmi_dom *                    dom;
	struct iovec *                       vec;
	size_t                               vec_allocated;
	size_t                               vec_pos;
	struct iovec                         static_vec;
	size_t                               static_space;
	unsigned int                         first_seq;
	bool                                 wait_for_reply;
	struct kvmi_control_cmd_response_msg prefix;
	struct kvmi_control_cmd_response_msg suffix;
};

struct kvmi_set_registers_msg {
	struct kvmi_msg_hdr  hdr;
	struct kvmi_vcpu_hdr vcpu;
	struct kvm_regs      regs;
};

struct kvmi_set_page_access_msg {
	struct kvmi_msg_hdr         hdr;
	struct kvmi_set_page_access cmd;
};

struct kvmi_pause_vcpu_msg {
	struct kvmi_msg_hdr    hdr;
	struct kvmi_vcpu_hdr   vcpu;
	struct kvmi_pause_vcpu cmd;
};

static long        pagesize;
static kvmi_log_cb log_cb;
static void *      log_ctx;

static int recv_reply( struct kvmi_dom *dom, const struct kvmi_msg_hdr *req, void *dest, size_t *dest_size );

__attribute__(( constructor )) static void lib_init( void )
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
	snprintf( ctx->un_addr.sun_path, sizeof( ctx->un_addr.sun_path ), "%s", path );

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

static int kvmi_open_kvmmem( struct kvmi_dom *dom )
{
	if ( dom->mem_fd != -1 )
		return 0;

	dom->mem_fd = open( "/dev/kvmmem", O_RDWR );

	return dom->mem_fd < 0 ? -1 : 0;
}

static void kvmi_close_kvmmem( struct kvmi_dom *dom )
{
	if ( dom->mem_fd != -1 ) {
		close( dom->mem_fd );
		dom->mem_fd = -1;
	}
}

int kvmi_memory_mapping( void *d, bool enable )
{
	struct kvmi_dom *dom = d;

	if ( !enable ) {
		kvmi_close_kvmmem( dom );
		return 0;
	}

	return kvmi_open_kvmmem( dom );
}

static void check_if_disconnected( struct kvmi_dom *dom, int err, kvmi_timeout_t ms, bool can_timeout )
{
	if ( dom->disconnected || !err )
		return;

	if ( errno == ETIMEDOUT && ( can_timeout || ms == KVMI_NOWAIT ) )
		return;

	dom->disconnected = true;
}

static int do_wait( struct kvmi_dom *dom, bool write, kvmi_timeout_t ms, bool can_timeout )
{
	short         event = write ? POLLOUT : POLLIN;
	int           err;
	struct pollfd pfd[1] = {};

	pfd[0].fd     = dom->fd;
	pfd[0].events = event;

	do {
		err = poll( pfd, 1, ms );
	} while ( err < 0 && errno == EINTR );

	if ( !err ) {
		/*
		 * The man page does not specify if poll() sets errno to
		 * ETIMEDOUT before returning 0
		 */
		errno = ETIMEDOUT;
		goto out_err;
	}

	if ( err < 0 )
		goto out_err;

	if ( pfd[0].revents & POLLHUP ) {
		errno = EPIPE;
		goto out_err;
	}

	return 0;

out_err:
	check_if_disconnected( dom, errno, ms, can_timeout );
	return -1;
}

static ssize_t buff_read( struct kvmi_dom *dom, kvmi_timeout_t ms )
{
	ssize_t ret;

wait:
	if ( do_wait( dom, false, ms, false ) < 0 )
		return -1;

	do {
		ret = recv( dom->fd, dom->buff + dom->tail, sizeof( dom->buff ) - dom->tail, 0 );
	} while ( ret < 0 && errno == EINTR );

	if ( !ret ) {
		errno             = ENOTCONN;
		dom->disconnected = true;
		return -1;
	}

	if ( ret < 0 ) {
		if ( errno == EAGAIN || errno == EWOULDBLOCK )
			/* go wait for the socket to become available again */
			goto wait;
		check_if_disconnected( dom, errno, ms, false );
		return -1;
	}

	return ret;
}

static int __do_read( struct kvmi_dom *dom, void *buf, size_t size, kvmi_timeout_t ms )
{
	char *dest = buf;

	errno = 0;

	while ( size ) {
		size_t  cached = dom->tail - dom->head;
		ssize_t n;

		if ( cached ) {
			size_t bytes = MIN( size, cached );

			memcpy( dest, dom->buff + dom->head, bytes );

			if ( bytes == cached )
				dom->head = dom->tail = 0;
			else
				dom->head += bytes;

			dest += bytes;
			size -= bytes;

			if ( !size )
				break;
		}

		n = buff_read( dom, ms );

		if ( n < 0 )
			return -1;

		dom->tail += n;
	}

	return 0;
}

static int do_read( struct kvmi_dom *dom, void *buf, size_t size )
{
	return __do_read( dom, buf, size, KVMI_MAX_TIMEOUT );
}

static int do_write( struct kvmi_dom *dom, struct iovec *iov, size_t iovlen )
{
	struct msghdr msg = { .msg_iov = iov, .msg_iovlen = iovlen };

	errno = 0;

	for ( ;; ) {
		ssize_t n;

		if ( do_wait( dom, true, KVMI_MAX_TIMEOUT, false ) < 0 )
			return -1;

		do {
			n = sendmsg( dom->fd, &msg, MSG_NOSIGNAL );
		} while ( n < 0 && errno == EINTR );

		if ( n >= 0 )
			break;

		if ( errno != EAGAIN && errno != EWOULDBLOCK ) {
			check_if_disconnected( dom, errno, KVMI_MAX_TIMEOUT, false );
			return -1;
		}
	}

	return 0;
}

static int consume_bytes( struct kvmi_dom *dom, size_t size )
{
	while ( size ) {
		unsigned char buf[1024];
		size_t        chunk = ( size < sizeof( buf ) ) ? size : sizeof( buf );

		if ( do_read( dom, buf, chunk ) )
			return -1;

		size -= chunk;
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

	if ( version < MIN_KVMI_VERSION ) {
		kvmi_log_error( "invalid protocol version (received 0x%08x, expected at least 0x%08x)", version,
		                MIN_KVMI_VERSION );
		return true;
	}

	dom->api_version = version;

	return false;
}

static int read_qemu_data( struct kvmi_dom *dom, struct kvmi_qemu2introspector *qemu )
{
	size_t incoming, useful;
	void * ptr;

	memset( qemu, 0, sizeof( *qemu ) );

	if ( do_read( dom, &qemu->struct_size, sizeof( qemu->struct_size ) ) )
		return -1;

	incoming = qemu->struct_size;

	if ( incoming < MIN_HANDSHAKE_DATA ) {
		errno = ENODATA;
		return -1;
	}

	if ( incoming > MAX_HANDSHAKE_DATA ) {
		errno = E2BIG;
		return -1;
	}

	qemu->struct_size = MIN( incoming, sizeof( *qemu ) );
	ptr               = ( char * )qemu + sizeof( qemu->struct_size );
	useful            = qemu->struct_size - sizeof( qemu->struct_size );

	if ( do_read( dom, ptr, useful ) )
		return -1;

	qemu->name[sizeof( qemu->name ) - 1] = 0;

	incoming -= sizeof( qemu->struct_size );
	incoming -= useful;

	return consume_bytes( dom, incoming );
}

static bool handshake_done( struct kvmi_ctx *ctx, struct kvmi_dom *dom )
{
	struct kvmi_qemu2introspector *qemu  = &dom->hsk;
	struct kvmi_introspector2qemu  intro = {};
	struct iovec                   iov   = { .iov_base = &intro, .iov_len = sizeof( intro ) };

	if ( read_qemu_data( dom, qemu ) ) {
		kvmi_log_error( "Invalid handshake data" );
		return false;
	}

	intro.struct_size = sizeof( intro );
	if ( ctx->handshake_cb && ctx->handshake_cb( qemu, &intro, ctx->cb_ctx ) < 0 )
		return false;

	return do_write( dom, &iov, 1 ) == 0;
}

/* The same sequence variable is used by all domains. */
static unsigned int new_seq( void )
{
	static unsigned int seq;

	return __sync_add_and_fetch( &seq, 1 );
}

void *kvmi_batch_alloc( void *dom )
{
	struct kvmi_batch *grp;
	size_t             allocated = pagesize * 4;

	grp = calloc( 1, allocated );
	if ( grp ) {
		grp->dom = dom;

		grp->static_vec.iov_base = grp + 1;
		grp->static_space        = allocated - sizeof( *grp );
		grp->first_seq           = new_seq();
		grp->wait_for_reply      = true;
	}

	return grp;
}

void kvmi_batch_free( void *_grp )
{
	struct kvmi_batch *grp = _grp;
	struct iovec *     iov;

	if ( !grp )
		return;

	iov = grp->vec;
	if ( iov ) {
		for ( ; grp->vec_allocated--; iov++ )
			if ( iov->iov_base != grp->static_vec.iov_base )
				free( iov->iov_base );

		free( grp->vec );
	}

	free( grp );
}

static int kvmi_enlarge_batch_iovec( struct kvmi_batch *grp )
{
	size_t        old_size = grp->vec_allocated;
	size_t        new_size = ( old_size + 1 ) * 2;
	struct iovec *new_ptr;

	new_ptr = realloc( grp->vec, new_size * sizeof( *grp->vec ) );
	if ( !new_ptr )
		return -1;

	grp->vec = new_ptr;
	memset( grp->vec + old_size, 0, ( new_size - old_size ) * sizeof( *grp->vec ) );
	grp->vec_allocated = new_size;

	return 0;
}

static bool message_added_to_static_buffer( struct kvmi_batch *grp, const void *src, size_t src_size )
{
	size_t dest_space;
	char * dest;

	if ( grp->vec )
		return false;

	dest       = ( char * )grp->static_vec.iov_base + grp->static_vec.iov_len;
	dest_space = grp->static_space - grp->static_vec.iov_len;

	if ( src_size > dest_space )
		return false;

	memcpy( dest, src, src_size );

	grp->static_vec.iov_len += src_size;

	return true;
}

static int kvmi_batch_add( struct kvmi_batch *grp, const void *data, size_t data_size )
{
	struct iovec *iov;

	if ( !data_size )
		return 0;

	if ( message_added_to_static_buffer( grp, data, data_size ) )
		return 0;

	if ( grp->vec_pos == MAX_BATCH_IOVS ) {
		errno = E2BIG;
		return -1;
	}

	if ( grp->vec_pos == grp->vec_allocated ) {
		if ( kvmi_enlarge_batch_iovec( grp ) )
			return -1;

		if ( grp->vec_pos == 0 ) {
			grp->vec[0].iov_base = grp->static_vec.iov_base;
			grp->vec[0].iov_len  = grp->static_vec.iov_len;
			grp->vec_pos         = 1;
		}
	}

	iov = grp->vec + grp->vec_pos;

	iov->iov_base = malloc( data_size );
	if ( !iov->iov_base )
		return -1;

	memcpy( iov->iov_base, data, data_size );
	iov->iov_len = data_size;

	grp->vec_pos++;

	return 0;
}

static void setup_kvmi_control_cmd_response_msg( struct kvmi_control_cmd_response_msg *msg, bool enable, bool now,
                                                 unsigned int seq )
{
	memset( msg, 0, sizeof( *msg ) );

	msg->hdr.id   = KVMI_CONTROL_CMD_RESPONSE;
	msg->hdr.seq  = seq;
	msg->hdr.size = sizeof( *msg ) - sizeof( msg->hdr );

	msg->cmd.enable = enable;
	msg->cmd.now    = now ? 1 : 0;
}

static void disable_command_reply( struct kvmi_control_cmd_response_msg *msg, unsigned int seq )
{
	setup_kvmi_control_cmd_response_msg( msg, false, true, seq );
}

static void enable_command_reply( struct kvmi_control_cmd_response_msg *msg, bool now )
{
	setup_kvmi_control_cmd_response_msg( msg, true, now, new_seq() );
}

static bool batch_with_event_reply_only( struct iovec *iov )
{
	struct kvmi_msg_hdr *hdr              = iov->iov_base;
	bool                 one_msg_in_iovec = ( iov->iov_len == sizeof( *hdr ) + hdr->size );

	return ( one_msg_in_iovec && hdr->id == KVMI_EVENT_REPLY );
}

static struct iovec *alloc_iovec( struct kvmi_batch *grp, struct iovec *buf, size_t buf_size, size_t *iov_cnt )
{
	struct iovec *iov, *new_iov;
	size_t        n, new_n;

	if ( grp->vec_pos ) {
		n   = grp->vec_pos;
		iov = grp->vec;
	} else if ( grp->static_vec.iov_len ) {
		n   = 1;
		iov = &grp->static_vec;
	} else {
		n   = 0;
		iov = buf;
	}

	if ( n == 0 || ( n == 1 && batch_with_event_reply_only( iov ) ) ) {
		*iov_cnt = n;
		return iov;
	}

	new_n = n + 2;

	if ( new_n <= buf_size )
		new_iov = buf;
	else {
		new_iov = calloc( new_n, sizeof( *new_iov ) );
		if ( !new_iov )
			return NULL;
	}

	disable_command_reply( &grp->prefix, grp->first_seq );
	new_iov[0].iov_base = &grp->prefix;
	new_iov[0].iov_len  = sizeof( grp->prefix );

	memcpy( new_iov + 1, iov, n * sizeof( *iov ) );

	enable_command_reply( &grp->suffix, grp->wait_for_reply );
	new_iov[n + 1].iov_base = &grp->suffix;
	new_iov[n + 1].iov_len  = sizeof( grp->suffix );

	*iov_cnt = new_n;
	return new_iov;
}

static void free_iovec( struct iovec *iov, struct kvmi_batch *grp, struct iovec *buf )
{
	if ( iov != buf && iov != grp->vec && iov != &grp->static_vec )
		free( iov );
}

int kvmi_batch_commit( void *_grp )
{
	struct kvmi_batch *grp = _grp;
	struct kvmi_dom *  dom;
	struct iovec       buf_iov[30];
	struct iovec *     iov = NULL;
	size_t             n   = 0;
	int                err = 0;

	iov = alloc_iovec( grp, buf_iov, sizeof( buf_iov ) / sizeof( buf_iov[0] ), &n );
	if ( !iov )
		return -1;
	if ( !n )
		goto out;

	dom = grp->dom;

	pthread_mutex_lock( &dom->lock );

	err = do_write( dom, iov, n );
	if ( !err && grp->wait_for_reply )
		err = recv_reply( dom, &grp->suffix.hdr, NULL, NULL );

	pthread_mutex_unlock( &dom->lock );

out:
	free_iovec( iov, grp, buf_iov );

	return err;
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

	kvmi_close_kvmmem( dom );

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

static int kvmi_send_msg( struct kvmi_dom *dom, unsigned short msg_id, unsigned msg_seq, const void *data,
                          size_t data_size )
{
	struct kvmi_msg_hdr hdr   = { .id = msg_id, .seq = msg_seq, .size = data_size };
	struct iovec        iov[] = {
                { .iov_base = &hdr, .iov_len = sizeof( hdr ) },
                { .iov_base = ( void * )data, .iov_len = data_size },
	};
	size_t n = data_size ? 2 : 1;

	return do_write( dom, iov, n );
}

static bool is_event( unsigned msg_id )
{
	return ( msg_id == KVMI_EVENT );
}

static int copy_event_common_data( struct kvmi_dom_event *ev, size_t *incoming )
{
	const struct kvmi_event *in_common    = ( const struct kvmi_event * )ev->buf;
	struct kvmi_event *      out_common   = &ev->event.common;
	size_t                   min_msg_size = offsetof( struct kvmi_event, arch );
	size_t                   useful       = MIN( in_common->size, sizeof( *out_common ) );

	if ( in_common->size > *incoming || in_common->size < min_msg_size )
		return -1;

	if ( useful )
		memcpy( out_common, in_common, useful );

	*incoming -= in_common->size;

	return 0;
}

static int expected_event_data_size( size_t event_id, size_t *size )
{
	static const size_t unknown = 0;
	static const size_t sz[]    = {
                [KVMI_EVENT_BREAKPOINT]  = sizeof( struct kvmi_event_breakpoint ),
                [KVMI_EVENT_CREATE_VCPU] = 1,
                [KVMI_EVENT_CR]          = sizeof( struct kvmi_event_cr ),
                [KVMI_EVENT_DESCRIPTOR]  = sizeof( struct kvmi_event_descriptor ),
                [KVMI_EVENT_HYPERCALL]   = 1,
                [KVMI_EVENT_MSR]         = sizeof( struct kvmi_event_msr ),
                [KVMI_EVENT_PAUSE_VCPU]  = 1,
                [KVMI_EVENT_PF]          = sizeof( struct kvmi_event_pf ),
                [KVMI_EVENT_TRAP]        = sizeof( struct kvmi_event_trap ),
                [KVMI_EVENT_UNHOOK]      = 1,
                [KVMI_EVENT_XSETBV]      = 1,
                [KVMI_EVENT_SINGLESTEP]  = 1,
	};

	if ( event_id >= sizeof( sz ) / sizeof( sz[0] ) || sz[event_id] == unknown )
		return -1;

	*size = sz[event_id] & ~1;
	return 0;
}

static int copy_event_specific_data( struct kvmi_dom_event *ev, size_t incoming )
{
	const struct kvmi_event *   in_common = ( const struct kvmi_event * )ev->buf;
	const struct kvmi_event_cr *in_cr     = ( const struct kvmi_event_cr * )( ev->buf + in_common->size );
	struct kvmi_event_cr *      out_cr    = &ev->event.cr;
	size_t                      expected;
	size_t                      useful;

	if ( expected_event_data_size( ev->event.common.event, &expected ) )
		return -1;

	useful = MIN( expected, incoming );
	if ( useful )
		memcpy( out_cr, in_cr, useful );

	return 0;
}

/*
 * newer/extended event:
 *     received: [ common    ] [ specific      ]
 *     internal: [ common ] [ specific ]
 * older/smaller event:
 *     received: [ common ] [ specific ]
 *     internal: [ common       ] [ specific      ]
 */
static int kvmi_read_event_data( struct kvmi_dom *dom, struct kvmi_dom_event *ev, size_t msg_size, kvmi_timeout_t ms )
{
	size_t max_msg_size = sizeof( ev->buf );

	if ( msg_size > max_msg_size )
		goto out_inval;

	if ( __do_read( dom, &ev->buf, msg_size, ms ) )
		return -1;

	if ( copy_event_common_data( ev, &msg_size ) )
		goto out_inval;

	if ( copy_event_specific_data( ev, msg_size ) )
		goto out_inval;

	return 0;

out_inval:
	errno = EINVAL;
	return -1;
}

static int kvmi_push_event( struct kvmi_dom *dom, unsigned int seq, unsigned int size, kvmi_timeout_t ms )
{
	bool                   queued = true;
	struct kvmi_dom_event *new_event;

	new_event = calloc( 1, sizeof( *new_event ) );
	if ( !new_event )
		return -1;

	if ( kvmi_read_event_data( dom, new_event, size, ms ) ) {
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
		dom->events = ( *event )->next;

		if ( --dom->event_count == 0 )
			dom->event_last = NULL;

		( *event )->next = NULL;
	}
	pthread_mutex_unlock( &dom->event_lock );

	if ( *event == NULL ) {
		errno = EAGAIN;
		return -1;
	}

	return 0;
}

static int recv_reply_header( struct kvmi_dom *dom, const struct kvmi_msg_hdr *req, size_t *size )
{
	struct kvmi_msg_hdr h;

	while ( !do_read( dom, &h, sizeof( h ) ) ) {
		if ( is_event( h.id ) ) {
			if ( kvmi_push_event( dom, h.seq, h.size, KVMI_WAIT ) )
				break;
		} else if ( h.id != req->id || h.seq != req->seq ) {
			errno = ENOMSG;
			kvmi_log_error( "Wrong message %u instead of %u (seq %u/%u)", h.id, req->id, h.seq, req->seq );
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

static int recv_error_code( struct kvmi_dom *dom, size_t *msg_size )
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

static int recv_reply_data( struct kvmi_dom *dom, size_t incoming, void *dest, size_t *dest_size )
{
	size_t expected = dest_size ? *dest_size : 0;
	size_t useful   = MIN( incoming, expected );

	if ( useful && do_read( dom, dest, useful ) )
		return -1;

	if ( incoming > useful )
		return consume_bytes( dom, incoming - useful );

	if ( expected > useful ) {
		size_t missing = expected - useful;

		memset( ( char * )dest + useful, 0, missing );

		*dest_size = useful;
	}

	return 0;
}

static int recv_reply( struct kvmi_dom *dom, const struct kvmi_msg_hdr *req, void *dest, size_t *dest_size )
{
	size_t incoming;

	if ( recv_reply_header( dom, req, &incoming ) )
		return -1;

	if ( recv_error_code( dom, &incoming ) )
		return -1;

	return recv_reply_data( dom, incoming, dest, dest_size );
}

static int request_raw( struct kvmi_dom *dom, const void *src, size_t src_size, void *dest, size_t *dest_size )
{
	struct iovec               iov = { .iov_base = ( void * )src, .iov_len = src_size };
	const struct kvmi_msg_hdr *req = src;
	int                        err;

	pthread_mutex_lock( &dom->lock );

	err = do_write( dom, &iov, 1 );
	if ( !err )
		err = recv_reply( dom, req, dest, dest_size );

	pthread_mutex_unlock( &dom->lock );

	return err;
}

static int request( struct kvmi_dom *dom, unsigned short msg_id, const void *src, size_t src_size, void *dest,
                    size_t *dest_size )
{
	int                 err;
	struct kvmi_msg_hdr req = { .id = msg_id, .seq = new_seq() };

	pthread_mutex_lock( &dom->lock );

	err = kvmi_send_msg( dom, msg_id, req.seq, src, src_size );

	if ( !err )
		err = recv_reply( dom, &req, dest, dest_size );

	pthread_mutex_unlock( &dom->lock );

	return err;
}

int kvmi_control_events( void *dom, unsigned short vcpu, int id, bool enable )
{
	struct {
		struct kvmi_vcpu_hdr       vcpu;
		struct kvmi_control_events cmd;
	} req = { .vcpu = { .vcpu = vcpu }, .cmd = { .event_id = id, .enable = enable } };

	return request( dom, KVMI_CONTROL_EVENTS, &req, sizeof( req ), NULL, NULL );
}

int kvmi_control_cr( void *dom, unsigned short vcpu, unsigned int cr, bool enable )
{
	struct {
		struct kvmi_vcpu_hdr   vcpu;
		struct kvmi_control_cr cmd;
	} req = { .vcpu = { .vcpu = vcpu }, .cmd = { .cr = cr, .enable = enable } };

	return request( dom, KVMI_CONTROL_CR, &req, sizeof( req ), NULL, NULL );
}

int kvmi_control_msr( void *dom, unsigned short vcpu, unsigned int msr, bool enable )
{
	struct {
		struct kvmi_vcpu_hdr    vcpu;
		struct kvmi_control_msr cmd;
	} req = { .vcpu = { .vcpu = vcpu }, .cmd = { .msr = msr, .enable = enable } };

	return request( dom, KVMI_CONTROL_MSR, &req, sizeof( req ), NULL, NULL );
}

static void setup_kvmi_pause_vcpu_msg( struct kvmi_pause_vcpu_msg *msg, unsigned short vcpu )
{
	memset( msg, 0, sizeof( *msg ) );

	msg->hdr.id   = KVMI_PAUSE_VCPU;
	msg->hdr.seq  = new_seq();
	msg->hdr.size = sizeof( *msg ) - sizeof( msg->hdr );

	msg->vcpu.vcpu = vcpu;
}

int kvmi_queue_pause_vcpu( void *grp, unsigned short vcpu )
{
	struct kvmi_pause_vcpu_msg msg;

	setup_kvmi_pause_vcpu_msg( &msg, vcpu );

	return kvmi_batch_add( grp, &msg, sizeof( msg ) );
}

int kvmi_pause_all_vcpus( void *dom, unsigned int count )
{
	struct kvmi_pause_vcpu_msg msg;
	unsigned short             vcpu;
	int                        err = -1;
	void *                     grp;

	if ( !count )
		return 0;

	grp = kvmi_batch_alloc( dom );
	if ( !grp )
		return -1;

	for ( vcpu = 0; vcpu < count; vcpu++ ) {

		setup_kvmi_pause_vcpu_msg( &msg, vcpu );

		msg.cmd.wait = 1;

		if ( kvmi_batch_add( grp, &msg, sizeof( msg ) ) )
			goto out;
	}

	if ( kvmi_batch_commit( grp ) )
		goto out;

	err = 0;
out:
	kvmi_batch_free( grp );

	return err;
}

int kvmi_get_page_access( void *dom, unsigned long long int gpa, unsigned char *access )
{
	struct kvmi_get_page_access *      req      = NULL;
	struct kvmi_get_page_access_reply *rpl      = NULL;
	size_t                             req_size = sizeof( *req ) + 1 * sizeof( req->gpa[0] );
	size_t                             rpl_size = sizeof( *rpl ) + 1 * sizeof( rpl->access[0] );
	int                                err      = -1;

	req = calloc( 1, req_size );
	rpl = malloc( rpl_size );
	if ( !req || !rpl )
		goto out;

	req->count  = 1;
	req->gpa[0] = gpa;

	err = request( dom, KVMI_GET_PAGE_ACCESS, req, req_size, rpl, &rpl_size );

	if ( !err )
		*access = rpl->access[0];

out:
	free( req );
	free( rpl );

	return err;
}

int kvmi_get_page_write_bitmap( void *dom, __u64 gpa, __u32 *bitmap )
{
	struct kvmi_get_page_write_bitmap *      req      = NULL;
	struct kvmi_get_page_write_bitmap_reply *rpl      = NULL;
	size_t                                   req_size = sizeof( *req ) + 1 * sizeof( req->gpa[0] );
	size_t                                   rpl_size = sizeof( *rpl ) + 1 * sizeof( rpl->bitmap[0] );
	int                                      err      = -1;

	req = malloc( req_size );
	rpl = malloc( rpl_size );
	if ( !req || !rpl )
		goto out;

	memset( req, 0, req_size );
	req->count  = 1;
	req->gpa[0] = gpa;

	err = request( dom, KVMI_GET_PAGE_WRITE_BITMAP, req, req_size, rpl, &rpl_size );

	if ( !err )
		*bitmap = rpl->bitmap[0];

out:
	free( req );
	free( rpl );

	return err;
}

static void *alloc_kvmi_set_page_access_msg( unsigned long long int *gpa, unsigned char *access, unsigned short count,
                                             size_t *msg_size )
{
	struct kvmi_set_page_access_msg *msg;
	unsigned int                     k;

	*msg_size = sizeof( *msg ) + count * sizeof( msg->cmd.entries[0] );
	msg       = calloc( 1, *msg_size );
	if ( !msg )
		return NULL;

	msg->hdr.id   = KVMI_SET_PAGE_ACCESS;
	msg->hdr.seq  = new_seq();
	msg->hdr.size = *msg_size - sizeof( msg->hdr );

	msg->cmd.count = count;

	for ( k = 0; k < count; k++ ) {
		msg->cmd.entries[k].gpa    = gpa[k];
		msg->cmd.entries[k].access = access[k];
	}

	return msg;
}

int kvmi_set_page_access( void *dom, unsigned long long int *gpa, unsigned char *access, unsigned short count )
{
	void * msg;
	size_t msg_size;
	int    err = -1;

	msg = alloc_kvmi_set_page_access_msg( gpa, access, count, &msg_size );
	if ( msg ) {
		err = request_raw( dom, msg, msg_size, NULL, NULL );
		free( msg );
	}

	return err;
}

int kvmi_queue_page_access( void *grp, unsigned long long int *gpa, unsigned char *access, unsigned short count )
{
	struct kvmi_set_page_access_msg *msg;
	size_t                           msg_size;
	int                              err = -1;

	msg = alloc_kvmi_set_page_access_msg( gpa, access, count, &msg_size );
	if ( !msg )
		return -1;

	err = kvmi_batch_add( grp, msg, msg_size );

	free( msg );

	return err;
}

int kvmi_set_page_write_bitmap( void *dom, __u64 *gpa, __u32 *bitmap, unsigned short count )
{
	struct kvmi_set_page_write_bitmap *req;
	size_t                             req_size = sizeof( *req ) + count * sizeof( req->entries[0] );
	int                                err      = -1, k;

	req = malloc( req_size );
	if ( !req )
		return -1;

	memset( req, 0, req_size );
	req->count = count;

	for ( k = 0; k < count; k++ ) {
		req->entries[k].gpa    = gpa[k];
		req->entries[k].bitmap = bitmap[k];
	}

	err = request( dom, KVMI_SET_PAGE_WRITE_BITMAP, req, req_size, NULL, NULL );

	free( req );

	return err;
}

int kvmi_get_vcpu_count( void *dom, unsigned int *count )
{
	struct kvmi_get_guest_info_reply rpl;
	size_t                           received = sizeof( rpl );
	int                              err;

	err = request( dom, KVMI_GET_GUEST_INFO, NULL, 0, &rpl, &received );

	if ( !err )
		*count = rpl.vcpu_count;

	return err;
}

int kvmi_get_tsc_speed( void *dom, unsigned long long int *speed )
{
	struct kvmi_vcpu_hdr            req = { .vcpu = 0 };
	struct kvmi_get_vcpu_info_reply rpl;
	size_t                          received = sizeof( rpl );
	int                             err;

	err = request( dom, KVMI_GET_VCPU_INFO, &req, sizeof( req ), &rpl, &received );

	if ( !err )
		*speed = rpl.tsc_speed;

	return err;
}

int kvmi_get_cpuid( void *dom, unsigned short vcpu, unsigned int function, unsigned int index, unsigned int *eax,
                    unsigned int *ebx, unsigned int *ecx, unsigned int *edx )
{
	struct {
		struct kvmi_vcpu_hdr  vcpu;
		struct kvmi_get_cpuid cmd;
	} req = { .vcpu = { .vcpu = vcpu }, .cmd = { .function = function, .index = index } };
	struct kvmi_get_cpuid_reply rpl;
	size_t                      received = sizeof( rpl );
	int                         err;

	err = request( dom, KVMI_GET_CPUID, &req, sizeof( req ), &rpl, &received );

	if ( !err ) {
		*eax = rpl.eax;
		*ebx = rpl.ebx;
		*ecx = rpl.ecx;
		*edx = rpl.edx;
	}

	return err;
}

int kvmi_get_mtrr_type( void *dom, unsigned long long int gpa, unsigned char *type )
{
	struct {
		struct kvmi_vcpu_hdr      vcpu;
		struct kvmi_get_mtrr_type cmd;
	} req = { .vcpu = { .vcpu = 0 }, .cmd = { .gpa = gpa } };
	struct kvmi_get_mtrr_type_reply rpl;
	size_t                          received = sizeof( rpl );
	int                             err;

	err = request( dom, KVMI_GET_MTRR_TYPE, &req, sizeof( req ), &rpl, &received );

	if ( !err )
		*type = rpl.type;

	return err;
}

static int request_varlen_response( struct kvmi_dom *dom, unsigned short msg_id, const void *src, size_t src_size,
                                    size_t *rpl_size )
{
	struct kvmi_msg_hdr req = { .id = msg_id, .seq = new_seq() };

	if ( kvmi_send_msg( dom, msg_id, req.seq, src, src_size ) )
		return -1;

	if ( recv_reply_header( dom, &req, rpl_size ) )
		return -1;

	if ( recv_error_code( dom, rpl_size ) )
		return -1;

	return 0;
}

int kvmi_get_xsave( void *dom, unsigned short vcpu, void *buffer, size_t buf_size )
{
	struct kvmi_vcpu_hdr req = { .vcpu = vcpu };

	return request( dom, KVMI_GET_XSAVE, &req, sizeof( req ), buffer, &buf_size );
}

int kvmi_inject_exception( void *dom, unsigned short vcpu, unsigned long long int gva, unsigned int error, unsigned char vector )
{
	struct {
		struct kvmi_vcpu_hdr         vcpu;
		struct kvmi_inject_exception cmd;
	} req = { .vcpu = { .vcpu = vcpu },
		  .cmd  = { .nr = vector, .error_code = error, .address = gva } };

	return request( dom, KVMI_INJECT_EXCEPTION, &req, sizeof( req ), NULL, NULL );
}

int kvmi_read_physical( void *dom, unsigned long long int gpa, void *buffer, size_t size )
{
	struct kvmi_read_physical req = { .gpa = gpa, .size = size };

	return request( dom, KVMI_READ_PHYSICAL, &req, sizeof( req ), buffer, &size );
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

	err = request( dom, KVMI_WRITE_PHYSICAL, req, req_size, NULL, NULL );

	free( req );

	return err;
}

void *kvmi_map_physical_page( void *d, unsigned long long int gpa )
{
	struct kvmi_dom *dom = d;

	errno = 0;

	void *addr = mmap( NULL, pagesize, PROT_READ | PROT_WRITE,
	                   MAP_LOCKED | MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );

	if ( addr != MAP_FAILED ) {
		struct kvmi_get_map_token_reply req;
		struct kvmi_mem_map             map_req;
		int                             retries = 0;
		int                             err;

		do {
			size_t received = sizeof( req );

			err = request( dom, KVMI_GET_MAP_TOKEN, NULL, 0, &req, &received );

			if ( !err ) {
				/* fill IOCTL arg */
				memcpy( &map_req.token, &req.token, sizeof( struct kvmi_map_mem_token ) );
				map_req.gpa = gpa;
				map_req.gva = ( __u64 )addr;

				/* do map IOCTL request */
				err = ioctl( dom->mem_fd, KVM_INTRO_MEM_MAP, &map_req );
			}

			if ( err && ( errno == EAGAIN || errno == EBUSY ) ) {
				if ( retries++ == MAP_RETRY_WARNING )
					kvmi_log_warning( "Slow mapping for gpa %llx", gpa );
				if ( retries < MAX_MAP_RETRIES )
					sleep( MAP_RETRY_SLEEP_SECS );
			} else
				break;
		} while ( retries < MAX_MAP_RETRIES );

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
	struct {
		struct kvmi_vcpu_hdr      vcpu;
		struct kvmi_get_registers regs;
	} * req;

	*req_size = sizeof( *req ) + sizeof( __u32 ) * msrs->nmsrs;
	req       = calloc( 1, *req_size );

	if ( req ) {
		unsigned int k = 0;

		req->vcpu.vcpu  = vcpu;
		req->regs.nmsrs = msrs->nmsrs;

		for ( ; k < msrs->nmsrs; k++ )
			req->regs.msrs_idx[k] = msrs->entries[k].index;
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
	struct kvmi_dom *dom = d;
	void *           req;
	size_t           req_size;
	size_t           received;
	int              err = -1;

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

static void setup_kvmi_set_registers_msg( struct kvmi_set_registers_msg *msg, unsigned short vcpu,
                                          const struct kvm_regs *regs )
{
	memset( msg, 0, sizeof( *msg ) );

	msg->hdr.id   = KVMI_SET_REGISTERS;
	msg->hdr.seq  = new_seq();
	msg->hdr.size = sizeof( *msg ) - sizeof( msg->hdr );

	msg->vcpu.vcpu = vcpu;
	msg->regs      = *regs;
}

int kvmi_queue_registers( void *grp, unsigned short vcpu, const struct kvm_regs *regs )
{
	struct kvmi_set_registers_msg msg;

	setup_kvmi_set_registers_msg( &msg, vcpu, regs );

	return kvmi_batch_add( grp, &msg, sizeof( msg ) );
}

int kvmi_set_registers( void *dom, unsigned short vcpu, const struct kvm_regs *regs )
{
	struct kvmi_set_registers_msg msg;

	setup_kvmi_set_registers_msg( &msg, vcpu, regs );

	return request_raw( dom, &msg, sizeof( msg ), NULL, NULL );
}

static void setup_reply_header( struct kvmi_msg_hdr *hdr, unsigned int seq, size_t msg_size )
{
	memset( hdr, 0, sizeof( *hdr ) );

	hdr->id   = KVMI_EVENT_REPLY;
	hdr->seq  = seq;
	hdr->size = msg_size;
}

int kvmi_queue_reply_event( void *grp, unsigned int seq, const void *data, size_t data_size )
{
	struct kvmi_msg_hdr hdr;

	setup_reply_header( &hdr, seq, data_size );

	if ( kvmi_batch_add( grp, &hdr, sizeof( hdr ) ) )
		return -1;

	if ( kvmi_batch_add( grp, data, data_size ) )
		return -1;

	( ( struct kvmi_batch * )grp )->wait_for_reply = false;
	return 0;
}

int kvmi_reply_event( void *_dom, unsigned int seq, const void *data, size_t data_size )
{
	struct kvmi_dom *   dom = _dom;
	struct kvmi_msg_hdr hdr;
	struct iovec        iov[] = {
                { .iov_base = &hdr, .iov_len = sizeof( hdr ) },
                { .iov_base = ( void * )data, .iov_len = data_size },
	};
	int err;

	setup_reply_header( &hdr, seq, data_size );

	pthread_mutex_lock( &dom->lock );

	err = do_write( dom, iov, 2 );

	pthread_mutex_unlock( &dom->lock );

	return err;
}

int kvmi_get_version( void *dom, unsigned int *version )
{
	struct kvmi_get_version_reply rpl;
	size_t                        received = sizeof( rpl );
	int                           err;

	err = request( dom, KVMI_GET_VERSION, NULL, 0, &rpl, &received );

	if ( !err )
		*version = rpl.version;

	return err;
}

int kvmi_check_command( void *dom, int id )
{
	struct kvmi_check_command req = { .id = id };

	return request( dom, KVMI_CHECK_COMMAND, &req, sizeof( req ), NULL, NULL );
}

int kvmi_check_event( void *dom, int id )
{
	struct kvmi_check_command req = { .id = id };

	return request( dom, KVMI_CHECK_EVENT, &req, sizeof( req ), NULL, NULL );
}

int kvmi_control_vm_events( void *dom, int id, bool enable )
{
	struct kvmi_control_vm_events req = { .event_id = id, .enable = enable };

	return request( dom, KVMI_CONTROL_VM_EVENTS, &req, sizeof( req ), NULL, NULL );
}

static int kvmi_read_event_header( struct kvmi_dom *dom, unsigned int *id, unsigned int *size, unsigned int *seq,
                                   kvmi_timeout_t ms )
{
	struct kvmi_msg_hdr h;

	if ( __do_read( dom, &h, sizeof( h ), ms ) )
		return -1;

	*id   = h.id;
	*seq  = h.seq;
	*size = h.size;

	return 0;
}

static int kvmi_read_event( struct kvmi_dom *dom, kvmi_timeout_t ms )
{
	unsigned int msgid;
	unsigned int msgsize;
	unsigned int msgseq;

	if ( kvmi_read_event_header( dom, &msgid, &msgsize, &msgseq, ms ) )
		return -1;

	if ( !is_event( msgid ) ) {
		errno = EINVAL;
		return -1;
	}

	return kvmi_push_event( dom, msgseq, msgsize, ms );
}

int kvmi_wait_event( void *d, kvmi_timeout_t ms )
{
	bool             empty;
	int              err;
	struct kvmi_dom *dom = d;

	/* Don't wait for events if there is one already queued. */
	pthread_mutex_lock( &dom->event_lock );
	empty = dom->events == NULL;
	pthread_mutex_unlock( &dom->event_lock );

	if ( !empty )
		return 0;
	/*
	 * This ugly code is needed so that we do not block other threads
	 * that are trying to send commands while we are waiting for events.
	 */
	pthread_mutex_lock( &dom->lock );
	if ( dom->tail - dom->head ) {
		/*
		 * The buffer is not empty. As we are shielded by the lock, it
		 * can be nothing else than an event (complete or partially).
		 */
		err = kvmi_read_event( dom, KVMI_NOWAIT );
		pthread_mutex_unlock( &dom->lock );
	} else {
		pthread_mutex_unlock( &dom->lock );
		/* Wait for events without blocking too much other threads. */
		err = do_wait( dom, false, ms, true );
		if ( !err ) {
			pthread_mutex_lock( &dom->lock );
			/*
			 * It is possible that we've lost the chance to read the
			 * event, someone else might have queued it. So, we don't
			 * wait at all. We'll get it next time from the queue.
			 */
			err = kvmi_read_event( dom, KVMI_NOWAIT );
			pthread_mutex_unlock( &dom->lock );
		}
	}

	return err;
}

void kvmi_set_log_cb( kvmi_log_cb cb, void *ctx )
{
	log_cb  = cb;
	log_ctx = ctx;
}

int kvmi_get_maximum_gfn( void *dom, unsigned long long *gfn )
{
	struct kvmi_get_max_gfn_reply rpl;
	size_t received = sizeof( rpl );
	int err;

	err = request( dom, KVMI_GET_MAX_GFN, NULL, 0, &rpl, &received );
	if ( !err )
		*gfn = rpl.gfn;

	return err;
}

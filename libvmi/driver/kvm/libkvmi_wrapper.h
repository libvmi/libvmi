/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Mathieu Tarral (mathieu.tarral@ssi.gouv.fr)
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
#ifndef LIBKVMI_WRAPPER_H
#define LIBKVMI_WRAPPER_H

#include <stdint.h>
#include <libkvmi.h>

#include "private.h"

struct kvm_instance;

// wrapper struct
typedef struct {

    void *handle;

    void* (*kvmi_init_unix_socket)
    (const char *socket, kvmi_new_guest_cb accept_cb, kvmi_handshake_cb hsk_cb, void *cb_ctx);

    void* (*kvmi_init_vsock)
    (unsigned int port, kvmi_new_guest_cb accept_cb, kvmi_handshake_cb hsk_cb, void *cb_ctx);

    void (*kvmi_uninit)
    (void* ctx);

    void (*kvmi_close)
    (void* ctx);

    void (*kvmi_domain_close)
    (void *dom, bool do_shutdown);

    int (*kvmi_connection_fd)
    ( const void *dom );

    int (*kvmi_get_version)
    ( void *dom, unsigned int *version );

    int (*kvmi_control_events)
    (void *dom, unsigned short vcpu, int id, bool enable);

    int (*kvmi_control_vm_events)
    (void *dom, int id, bool enable);

    int (*kvmi_control_cr)
    (void *dom, unsigned short vcpu, unsigned int cr, bool enable);

    int (*kvmi_control_msr)
    (void *dom, unsigned short vcpu, unsigned int msr, bool enable);

    // singlestep only in KVMi-v7
    int (*kvmi_control_singlestep)
    (void *dom, unsigned short vcpu, bool enable);

    int (*kvmi_pause_all_vcpus)
    (void *dom, unsigned int count);

    int (*kvmi_set_page_access)
    (void *dom, unsigned long long int *gpa, unsigned char *access, unsigned short count,
     unsigned short view);

    int (*kvmi_get_tsc_speed)
    (void *dom, unsigned long long int *speed);

    int (*kvmi_get_vcpu_count)
    (void *dom, unsigned int *count);

    int (*kvmi_inject_exception)
    (void *dom, unsigned short vcpu, unsigned long long int gva, unsigned int error, unsigned char vector);

    int (*kvmi_read_physical)
    (void *dom, unsigned long long int gpa, void *buffer, size_t size);

    int (*kvmi_write_physical)
    (void *dom, unsigned long long int gpa, const void *buffer, size_t size);

    int (*kvmi_get_registers)
    (void *dom, unsigned short vcpu, struct kvm_regs *regs, struct kvm_sregs *sregs,
     struct kvm_msrs *msrs, unsigned int *mode);

    int (*kvmi_set_registers)
    (void *dom, unsigned short vcpu, const struct kvm_regs *regs);

    int (*kvmi_reply_event)
    (void *dom, unsigned int msg_seq, const void *data, size_t data_size);

    int (*kvmi_pop_event)
    (void *dom, struct kvmi_dom_event **event);

    int (*kvmi_wait_event)
    (void *dom, kvmi_timeout_t ms);

    void (*kvmi_set_log_cb)
    ( kvmi_log_cb cb, void *ctx );

    int (*kvmi_get_maximum_gfn)
    (void *dom, unsigned long long *gfn);

    // only on KVMi-v7
    int (*kvmi_spp_support)
    (void *dom, bool *supported);

    int (*kvmi_ve_support)
    (void *dom, bool *supported);

    int (*kvmi_vmfunc_support)
    (void *dom, bool *supported);

    int (*kvmi_eptp_support)
    (void *dom, bool *supported);

    size_t (*kvmi_get_pending_events)
    (void *dom);

} libkvmi_wrapper_t;

status_t create_libkvmi_wrapper(struct kvm_instance *kvm);

#endif // !LIBKVMI_WRAPPER_H

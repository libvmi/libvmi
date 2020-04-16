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
#include "kvm_private.h"
#include "libkvmi_wrapper.h"

static status_t sanity_check(kvm_instance_t *kvm)
{
    libkvmi_wrapper_t *w =
        &kvm->libkvmi;

    if ( !w->kvmi_init_unix_socket || !w->kvmi_uninit || !w->kvmi_close ||
            !w->kvmi_domain_close || !w->kvmi_connection_fd ||
            !w->kvmi_get_version || !w->kvmi_control_events ||
            !w->kvmi_control_vm_events || !w->kvmi_control_cr ||
            !w->kvmi_control_msr || !w->kvmi_pause_all_vcpus ||
            !w->kvmi_get_page_access || !w->kvmi_set_page_access || !w->kvmi_get_tsc_speed ||
            !w->kvmi_get_vcpu_count || !w->kvmi_inject_exception ||
            !w->kvmi_read_physical || !w->kvmi_write_physical ||
            !w->kvmi_get_registers || !w->kvmi_set_registers ||
            !w->kvmi_reply_event || !w->kvmi_pop_event || !w->kvmi_wait_event ||
            !w->kvmi_set_log_cb || !w->kvmi_get_maximum_gfn ) {
        dbprint(VMI_DEBUG_KVM, "--failed to find the required functions in libkvmi\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}


status_t create_libkvmi_wrapper(struct kvm_instance *kvm)
{
    libkvmi_wrapper_t *wrapper = &kvm->libkvmi;

    wrapper->handle = dlopen("libkvmi.so", RTLD_NOW | RTLD_GLOBAL);

    if (!wrapper->handle) {
        dbprint(VMI_DEBUG_KVM, "--failed to open a handle to libkvmi\n");
        return VMI_FAILURE;
    }

    wrapper->kvmi_init_unix_socket = dlsym(wrapper->handle, "kvmi_init_unix_socket");
    wrapper->kvmi_uninit = dlsym(wrapper->handle, "kvmi_uninit");
    wrapper->kvmi_close = dlsym(wrapper->handle, "kvmi_close");
    wrapper->kvmi_domain_close = dlsym(wrapper->handle, "kvmi_domain_close");
    wrapper->kvmi_connection_fd = dlsym(wrapper->handle, "kvmi_connection_fd");
    wrapper->kvmi_get_version = dlsym(wrapper->handle, "kvmi_get_version");
    wrapper->kvmi_control_events = dlsym(wrapper->handle, "kvmi_control_events");
    wrapper->kvmi_control_vm_events = dlsym(wrapper->handle, "kvmi_control_vm_events");
    wrapper->kvmi_control_cr = dlsym(wrapper->handle, "kvmi_control_cr");
    wrapper->kvmi_control_msr = dlsym(wrapper->handle, "kvmi_control_msr");
    wrapper->kvmi_pause_all_vcpus = dlsym(wrapper->handle, "kvmi_pause_all_vcpus");
    wrapper->kvmi_get_page_access = dlsym(wrapper->handle, "kvmi_get_page_access");
    wrapper->kvmi_set_page_access = dlsym(wrapper->handle, "kvmi_set_page_access");
    wrapper->kvmi_get_tsc_speed = dlsym(wrapper->handle, "kvmi_get_tsc_speed");
    wrapper->kvmi_get_vcpu_count = dlsym(wrapper->handle, "kvmi_get_vcpu_count");
    wrapper->kvmi_inject_exception = dlsym(wrapper->handle, "kvmi_inject_exception");
    wrapper->kvmi_read_physical = dlsym(wrapper->handle, "kvmi_read_physical");
    wrapper->kvmi_write_physical = dlsym(wrapper->handle, "kvmi_write_physical");
    wrapper->kvmi_get_registers = dlsym(wrapper->handle, "kvmi_get_registers");
    wrapper->kvmi_set_registers = dlsym(wrapper->handle, "kvmi_set_registers");
    wrapper->kvmi_reply_event = dlsym(wrapper->handle, "kvmi_reply_event");
    wrapper->kvmi_pop_event = dlsym(wrapper->handle, "kvmi_pop_event");
    wrapper->kvmi_wait_event = dlsym(wrapper->handle, "kvmi_wait_event");
    wrapper->kvmi_set_log_cb = dlsym(wrapper->handle, "kvmi_set_log_cb");
    wrapper->kvmi_get_maximum_gfn = dlsym(wrapper->handle, "kvmi_get_maximum_gfn");

    status_t ret = sanity_check(kvm);
    if ( ret != VMI_SUCCESS ) {
        dlclose(wrapper->handle);
    }

    return ret;
}

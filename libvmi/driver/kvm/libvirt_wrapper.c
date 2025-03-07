/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel <tamas.lengyel@zentific.com>
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

#include <string.h>

#include "private.h"
#include "kvm_private.h"

static inline status_t sanity_check(kvm_instance_t *kvm)
{
    libvirt_wrapper_t *w = &kvm->libvirt;

    if ( !w->virConnectOpenAuth || !w->virConnectGetLibVersion || !w->virConnectAuthPtrDefault ||
            !w->virConnectClose || !w->virDomainGetName || !w->virDomainGetID ||
            !w->virDomainLookupByID || !w->virDomainLookupByName || !w->virDomainGetInfo ||
            !w->virDomainQemuMonitorCommand ||
            !w->virDomainFree || !w->virDomainSuspend || !w->virDomainResume ) {
        dbprint(VMI_DEBUG_KVM, "--failed to find the required functions in libvirt\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t create_libvirt_wrapper(kvm_instance_t *kvm)
{
    libvirt_wrapper_t *wrapper = &kvm->libvirt;

    wrapper->handle = dlopen("libvirt.so", RTLD_NOW | RTLD_GLOBAL);

    if ( !wrapper->handle ) {
        // fallback to libvirt.so.0
        wrapper->handle = dlopen("libvirt.so.0", RTLD_NOW | RTLD_GLOBAL);

        if ( !wrapper->handle ) {
            dbprint(VMI_DEBUG_KVM, "--failed to open a handle to libvirt\n");
            return VMI_FAILURE;
        }
    }

    wrapper->handle_qemu = dlopen ("libvirt-qemu.so", RTLD_NOW | RTLD_GLOBAL);

    if ( !wrapper->handle_qemu ) {
        // fallback to libvirt-qemu.so.0
        wrapper->handle_qemu = dlopen ("libvirt-qemu.so.0", RTLD_NOW | RTLD_GLOBAL);

        if ( !wrapper->handle_qemu ) {
            dbprint(VMI_DEBUG_KVM, "--failed to open a handle to libvirt-qemu\n");
            dlclose(wrapper->handle);
            return VMI_FAILURE;
        }
    }

    wrapper->virConnectOpenAuth = dlsym(wrapper->handle, "virConnectOpenAuth");
    wrapper->virConnectGetLibVersion = dlsym(wrapper->handle, "virConnectGetLibVersion");
    wrapper->virConnectClose = dlsym(wrapper->handle, "virConnectClose");
    wrapper->virDomainGetName = dlsym(wrapper->handle, "virDomainGetName");
    wrapper->virDomainGetID = dlsym(wrapper->handle, "virDomainGetID");
    wrapper->virDomainLookupByID = dlsym(wrapper->handle, "virDomainLookupByID");
    wrapper->virDomainLookupByName = dlsym(wrapper->handle, "virDomainLookupByName");
    wrapper->virDomainGetInfo = dlsym(wrapper->handle, "virDomainGetInfo");
    wrapper->virDomainFree = dlsym(wrapper->handle, "virDomainFree");
    wrapper->virDomainSuspend = dlsym(wrapper->handle, "virDomainSuspend");
    wrapper->virDomainResume = dlsym(wrapper->handle, "virDomainResume");
    wrapper->virConnectAuthPtrDefault = dlsym(wrapper->handle, "virConnectAuthPtrDefault");

    wrapper->virDomainQemuMonitorCommand = dlsym(wrapper->handle_qemu, "virDomainQemuMonitorCommand");

    status_t ret = sanity_check(kvm);
    if ( ret != VMI_SUCCESS ) {
        dlclose(wrapper->handle);
        dlclose(wrapper->handle_qemu);
    }

    return ret;
}

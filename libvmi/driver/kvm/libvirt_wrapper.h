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

#include <config.h>
#include <libvirt/libvirt.h>
#include <dlfcn.h>

#include "libvmi.h"

struct kvm_instance;

typedef struct {
    void *handle;

    virConnectPtr (*virConnectOpenAuth)
    (const char *name, virConnectAuthPtr auth, unsigned int flags);

    int (*virConnectGetLibVersion)
    (virConnectPtr conn, unsigned long *libVer);

    int (*virConnectClose)
    (virConnectPtr conn);

    const char* (*virDomainGetName)
    (virDomainPtr domain);

    unsigned int (*virDomainGetID)
    (virDomainPtr domain);

    virDomainPtr (*virDomainLookupByID)
    (virConnectPtr conn, int id);

    virDomainPtr (*virDomainLookupByName)
    (virConnectPtr conn, const char *name);

    int (*virDomainGetInfo)
    (virDomainPtr domain, virDomainInfoPtr info);

    int (*virDomainFree)
    (virDomainPtr domain);

    int (*virDomainSuspend)
    (virDomainPtr domain);

    int (*virDomainResume)
    (virDomainPtr domain);

    virConnectAuthPtr virConnectAuthPtrDefault;

} libvirt_wrapper_t;

status_t create_libvirt_wrapper(struct kvm_instance *kvm);

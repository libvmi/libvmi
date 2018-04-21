/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
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

#include <stdlib.h>
#include <string.h>

#include "private.h"
#include "driver/driver_interface.h"

#if ENABLE_FILE == 1
#include "driver/file/file.h"
#endif

#if ENABLE_XEN == 1
#include "driver/xen/xen.h"
#endif

#if ENABLE_KVM == 1
#include "driver/kvm/kvm.h"
#endif

status_t driver_init_mode(const char *name,
                          uint64_t domainid,
                          uint64_t init_flags,
                          void* init_data,
                          vmi_mode_t *mode)
{
    unsigned long count = 0;

    /* see what systems are accessable */
#if ENABLE_XEN == 1
    if (VMI_SUCCESS == xen_test(domainid, name, init_flags, init_data)) {
        dbprint(VMI_DEBUG_DRIVER, "--found Xen\n");
        *mode = VMI_XEN;
        count++;
    }
#endif
#if ENABLE_KVM == 1
    if (VMI_SUCCESS == kvm_test(domainid, name, init_flags, init_data)) {
        dbprint(VMI_DEBUG_DRIVER, "--found KVM\n");
        *mode = VMI_KVM;
        count++;
    }
#endif
#if ENABLE_FILE == 1
    if (VMI_SUCCESS == file_test(domainid, name, init_flags, init_data)) {
        dbprint(VMI_DEBUG_DRIVER, "--found file\n");
        *mode = VMI_FILE;
        count++;
    }
#endif

    /* if we didn't see exactly one system, report error */
    if (count == 0) {
        errprint("Could not find a live guest VM or file to use.\n");
        errprint("Opening a live guest VM requires root access.\n");
        return VMI_FAILURE;
    } else if (count > 1) {
        errprint
        ("Found more than one VMM or file to use,\nplease specify what you want instead of using VMI_AUTO.\n");
        return VMI_FAILURE;
    } else { // count == 1
        return VMI_SUCCESS;
    }
}

status_t driver_init(vmi_instance_t vmi,
                     uint32_t init_flags,
                     void *init_data)
{
    status_t rc = VMI_FAILURE;
    if (vmi->driver.initialized) {
        errprint("Driver is already initialized.\n");
        return rc;
    }

    bzero(&vmi->driver, sizeof(driver_interface_t));

    switch (vmi->mode) {
#if ENABLE_XEN == 1
        case VMI_XEN:
            rc = driver_xen_setup(vmi);
            break;
#endif
#if ENABLE_KVM == 1
        case VMI_KVM:
            rc = driver_kvm_setup(vmi);
            break;
#endif
#if ENABLE_FILE == 1
        case VMI_FILE:
            rc = driver_file_setup(vmi);
            break;
#endif
        default:
            break;
    };

    if (rc == VMI_SUCCESS && vmi->driver.init_ptr)
        rc = vmi->driver.init_ptr(vmi, init_flags, init_data);

    return rc;
}

status_t driver_init_vmi(vmi_instance_t vmi,
                         uint32_t init_flags,
                         void *init_data)
{
    status_t rc = VMI_FAILURE;
    if (vmi->driver.init_vmi_ptr)
        rc = vmi->driver.init_vmi_ptr(vmi, init_flags, init_data);

    return rc;
}

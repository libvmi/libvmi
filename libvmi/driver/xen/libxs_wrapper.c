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
#include "xen_private.h"

static status_t sanity_check(xen_instance_t *xen)
{
    libxs_wrapper_t *w = &xen->libxsw;

    if ( !w->xs_open || !w->xs_close || !w->xs_read || !w->xs_directory )
        return VMI_FAILURE;

    xen->xshandle = xen->libxsw.xs_open(0);
    if ( !xen->xshandle ) {
        errprint("Failed to open libxenstore interface.\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t create_libxs_wrapper(xen_instance_t *xen)
{
    libxs_wrapper_t *wrapper = &xen->libxsw;

    wrapper->handle = dlopen ("libxenstore.so", RTLD_NOW | RTLD_GLOBAL);
    if ( !wrapper->handle ) {
        fprintf(stderr, "Failed to find a suitable libxenstore.so at any of the standard paths!\n");
        return VMI_FAILURE;
    }

    wrapper->xs_open = dlsym(wrapper->handle, "xs_open");
    wrapper->xs_close = dlsym(wrapper->handle, "xs_close");
    wrapper->xs_directory = dlsym(wrapper->handle, "xs_directory");
    wrapper->xs_read = dlsym(wrapper->handle, "xs_read");

    return sanity_check(xen);
}

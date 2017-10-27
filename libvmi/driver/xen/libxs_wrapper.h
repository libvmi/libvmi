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
#include <dlfcn.h>

#if HAVE_XENSTORE_H
#include <xenstore.h>
#elif HAVE_XS_H
#include <xs.h>
#endif

#include "libvmi.h"

struct xen_instance;

#ifndef HAVE_LIBXENSTORE
struct xs_handle;
typedef struct xs_transaction xs_transaction_t;
#endif

typedef struct {
    struct xs_handle* handle;

    struct xs_handle* (*xs_open)
    (unsigned long flags);

    void (*xs_close)
    (struct xs_handle *xsh);

    char** (*xs_directory)
    (struct xs_handle *h, xs_transaction_t t, const char *path, unsigned int *num);

    void* (*xs_read)
    (struct xs_handle *h, xs_transaction_t t, const char *path, unsigned int *len);

} libxs_wrapper_t;

status_t create_libxs_wrapper(struct xen_instance *xen);

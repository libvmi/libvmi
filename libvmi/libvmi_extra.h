/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
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

/**
 * @file libvmi_extra.h
 * @brief The Extra LibVMI API is defined here.
 *
 * Include this header requires you to compile your application with GLib.
 */
#ifndef LIBVMI_EXTRA_H
#define LIBVMI_EXTRA_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

#include <glib.h>

/**
 * Retrieve the pages mapped into the address space of a process.
 * @param[in] vmi Instance
 * @param[in] dtb The directory table base of the process
 *
 * @return GSList of page_info_t structures, or NULL on error.
 * The caller is responsible for freeing the list and the structs.
 */
GSList* vmi_get_va_pages(
    vmi_instance_t vmi,
    addr_t dtb);

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif /* LIBVMI_EXTRA_H */

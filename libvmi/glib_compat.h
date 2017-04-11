/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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

/*
 * @file glib_compat.c
 * @brief Compatibility functions are defined here that enable use of LibVMI
 *  with versions of glib older than 2.22
 *
 */

#ifndef LIBVMI_GLIB_COMPAT_H
#define LIBVMI_GLIB_COMPAT_H

#if !GLIB_CHECK_VERSION(2,22,0)

/* Pointers to these convenience functions are passed as parameters to many other
 *  functions related to GHashTable initialization and manipulation, so we cannot
 *  employ any other (more pleasant) tricks that rely upon the pre-processor.
 */
static guint
g_int64_hash(
    gconstpointer v)
{
    return (guint) * (const gint64 *) v;
}

static gboolean
g_int64_equal(
    gconstpointer v1,
    gconstpointer v2)
{
    return *((const gint64 *) v1) == *((const gint64 *) v2);
}

#endif

static inline gboolean
g_hash_table_insert_compat(GHashTable *table,
                           gpointer key,
                           gpointer value)
{
#if GLIB_CHECK_VERSION(2,39,0)
    return g_hash_table_insert(table, key, value);
#else
    g_hash_table_insert(table, key, value);
    return true;
#endif
}

#endif

/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
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

#ifndef LIBVMI_DEBUG_H
#define LIBVMI_DEBUG_H

/*
 * This enum holds the various debug print-outs that can be generated
 */
typedef enum {
    VMI_DEBUG_MISC     = (1 << 0),
    VMI_DEBUG_MEMCACHE = (1 << 1),
    VMI_DEBUG_PIDCACHE = (1 << 2),
    VMI_DEBUG_SYMCACHE = (1 << 3),
    VMI_DEBUG_RVACACHE = (1 << 4),
    VMI_DEBUG_V2PCACHE = (1 << 5),
    VMI_DEBUG_V2MCACHE = (1 << 6),
    VMI_DEBUG_PTLOOKUP = (1 << 7),
    VMI_DEBUG_EVENTS   = (1 << 8),
    VMI_DEBUG_XEN      = (1 << 9),
    VMI_DEBUG_KVM      = (1 << 10),
    VMI_DEBUG_FILE     = (1 << 11),
    VMI_DEBUG_CORE     = (1 << 12),
    VMI_DEBUG_READ     = (1 << 13),
    VMI_DEBUG_WRITE    = (1 << 14),
    VMI_DEBUG_DRIVER   = (1 << 15),
    VMI_DEBUG_PEPARSE  = (1 << 16),

    __VMI_DEBUG_ALL    = ~(0ULL)
} vmi_debug_flag_t;

/* uncomment this and recompile to enable debug output */
//#define VMI_DEBUG __VMI_DEBUG_ALL

#endif

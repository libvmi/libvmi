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
#ifndef XEN_PRIVATE_H
#define XEN_PRIVATE_H

#define _GNU_SOURCE
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <xenctrl.h>
#if HAVE_XENSTORE_H
  #include <xenstore.h>
#elif HAVE_XS_H
  #include <xs.h>
#endif
#include <xen/hvm/save.h>

#include "private.h"

#if ENABLE_XEN_EVENTS == 1
  #include "driver/xen/xen_events_private.h"
#endif

/* compatibility checks */
#ifndef xen_cr3_to_pfn_x86_32
#define xen_pfn_to_cr3_x86_64(pfn) ((__align8__ uint64_t)(pfn) << 12)
#define xen_cr3_to_pfn_x86_64(cr3) ((__align8__ uint64_t)(cr3) >> 12)

#define xen_pfn_to_cr3_x86_32(pfn) (((unsigned)(pfn) << 12) | ((unsigned)(pfn) >> 20))
#define xen_cr3_to_pfn_x86_32(cr3) (((unsigned)(cr3) >> 12) | ((unsigned)(cr3) << 20))

#include <xen/memory.h>
#define xc_domain_maximum_gpfn(xch, domid) xc_memory_op(xch, XENMEM_maximum_gpfn, &domid)
#endif /* xen_cr3_to_pfn_x86_32 */

#ifdef XENCTRL_HAS_XC_INTERFACE // Xen >= 4.1
typedef xc_interface *libvmi_xenctrl_handle_t;

#define XENCTRL_HANDLE_INVALID NULL

    // new way to open/close XS daemon
#ifdef HAVE_LIBXENSTORE
#define OPEN_XS_DAEMON()    xs_open(0)
#define CLOSE_XS_DAEMON(h)  xs_close(h)
#endif
#else /* XENCTRL_HAS_XC_INTERFACE */
typedef int libvmi_xenctrl_handle_t;

#define XENCTRL_HANDLE_INVALID (-1)

#ifdef HAVE_LIBXENSTORE
    // these are supported, but deprecated in xen 4.1
#define OPEN_XS_DAEMON()     xs_daemon_open()
#define CLOSE_XS_DAEMON(h)   xs_daemon_close(h)
#endif /* HAVE_LIBXENSTORE */
#endif /* XENCTRL_HAS_XC_INTERFACE */

typedef struct xen_instance {

    char *name;

    libvmi_xenctrl_handle_t xchandle; /**< handle to xenctrl library (libxc) */

    uint64_t domainid; /**< domid that we are accessing */

    int xen_version;        /**< version of Xen libxa is running on */

    int hvm;                /**< nonzero if HVM */

    xc_dominfo_t info;      /**< libxc info: domid, ssidref, stats, etc */


#if __XEN_INTERFACE_VERSION__ < 0x00040600
    int max_gpfn;           /**< result of xc_domain_maximum_gpfn() */
#else
    xen_pfn_t max_gpfn;           /**< result of xc_domain_maximum_gpfn() */
#endif

    uint8_t addr_width;     /**< guest's address width in bytes: 4 or 8 */

#ifdef HAVE_LIBXENSTORE
    struct xs_handle *xshandle;  /**< handle to xenstore daemon */
#endif

#if ENABLE_XEN_EVENTS == 1
    xen_events_t *events; /**< handle to events data */
#endif

#if ENABLE_SHM_SNAPSHOT == 1
    char *shm_snapshot_path;  /** reserved for shared memory snapshot device path in /dev/shm directory */

    int   shm_snapshot_fd;    /** reserved for file description of the shared memory snapshot device */

    void *shm_snapshot_map;   /** reserved mapped shared memory region. It's currently malloc() regions */

    void *shm_snapshot_cpu_regs;  /** structure of dumped CPU registers */
#endif
} xen_instance_t;

static inline
xen_instance_t *xen_get_instance(
    vmi_instance_t vmi)
{
    return ((xen_instance_t *) vmi->driver.driver_data);
}

static inline
libvmi_xenctrl_handle_t xen_get_xchandle(
    vmi_instance_t vmi)
{
    return xen_get_instance(vmi)->xchandle;
}

#endif /* XEN_PRIVATE_H */

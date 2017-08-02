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
#define XC_WANT_COMPAT_EVTCHN_API 1
#define XC_WANT_COMPAT_MAP_FOREIGN_API 1
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <xenctrl.h>
#include <xen/hvm/save.h>

#include "private.h"
#include "libxc_wrapper.h"
#include "libxs_wrapper.h"
#include "driver/xen/xen_events_private.h"

typedef struct xen_instance {

    char *name;

    xc_interface* xchandle; /**< handle to xenctrl library (libxc) */

    struct xs_handle *xshandle;  /**< handle to xenstore daemon (libxs) */

    libxc_wrapper_t libxcw; /**< wrapper for libxc for cross-compatibility */

    libxs_wrapper_t libxsw; /**< wrapper for libxs for cross-compatibility */

    uint64_t domainid; /**< domid that we are accessing */

    int major_version;  /**< Major version of Xen LibMVI is running on */

    int minor_version;  /**< Minor version of Xen LibMVI is running on */

    vm_type_t type; /**< VM type (HVM/PV32/PV64) */

    xc_dominfo_t info;      /**< libxc info: domid, ssidref, stats, etc */

    xen_events_t *events; /**< handle to events data */

    uint64_t max_gpfn;    /**< result of xc_domain_maximum_gpfn/2() */

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
xc_interface* xen_get_xchandle(
    vmi_instance_t vmi)
{
    return xen_get_instance(vmi)->xchandle;
}

static inline xen_events_t*
xen_get_events(vmi_instance_t vmi)
{
    return xen_get_instance(vmi)->events;
}
#endif /* XEN_PRIVATE_H */

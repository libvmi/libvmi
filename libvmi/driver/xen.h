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

#include "driver/xen_events.h"

#if ENABLE_XEN == 1
#include <xenctrl.h>

/* compatibility checks */
#ifndef xen_cr3_to_pfn_x86_32
#define xen_pfn_to_cr3_x86_64(pfn) ((__align8__ uint64_t)(pfn) << 12)
#define xen_cr3_to_pfn_x86_64(cr3) ((__align8__ uint64_t)(cr3) >> 12)

#define xen_pfn_to_cr3_x86_32(pfn) (((unsigned)(pfn) << 12) | ((unsigned)(pfn) >> 20))
#define xen_cr3_to_pfn_x86_32(cr3) (((unsigned)(cr3) >> 12) | ((unsigned)(cr3) << 20))

#include <xen/memory.h>
#define xc_domain_maximum_gpfn(xch, domid) xc_memory_op(xch, XENMEM_maximum_gpfn, &domid)
#endif

#ifdef XENCTRL_HAS_XC_INTERFACE // Xen >= 4.1
typedef xc_interface *libvmi_xenctrl_handle_t;

#define XENCTRL_HANDLE_INVALID NULL

    // new way to open/close XS daemon
#ifdef HAVE_LIBXENSTORE
#define OPEN_XS_DAEMON()    xs_open(0)
#define CLOSE_XS_DAEMON(h)  xs_close(h)
#endif
#else
typedef int libvmi_xenctrl_handle_t;

#define XENCTRL_HANDLE_INVALID (-1)

#ifdef HAVE_LIBXENSTORE
    // these are supported, but deprecated in xen 4.1
#define OPEN_XS_DAEMON()     xs_daemon_open()
#define CLOSE_XS_DAEMON(h)   xs_daemon_close(h)
#endif
#endif

typedef struct xen_instance {

    libvmi_xenctrl_handle_t xchandle; /**< handle to xenctrl library (libxc) */

    unsigned long domainid; /**< domid that we are accessing */

    int xen_version;        /**< version of Xen libxa is running on */

    int hvm;                /**< nonzero if HVM */

    xc_dominfo_t info;      /**< libxc info: domid, ssidref, stats, etc */

    uint8_t addr_width;     /**< guest's address width in bytes: 4 or 8 */

#ifdef HAVE_LIBXENSTORE
    struct xs_handle *xshandle;  /**< handle to xenstore daemon */
#endif

    char *name;

#if ENABLE_XEN_EVENTS==1
    xen_events_t *events; /**< handle to events data */
#endif
} xen_instance_t;

#else

typedef struct xen_instance {
} xen_instance_t;

#endif /* ENABLE_XEN */

status_t xen_init(
    vmi_instance_t vmi);
void xen_destroy(
    vmi_instance_t vmi);
unsigned long xen_get_domainid_from_name(
    vmi_instance_t vmi,
    char *name);
status_t xen_get_name_from_domainid(
    vmi_instance_t vmi,
    unsigned long domid,
    char **name);
unsigned long xen_get_domainid(
    vmi_instance_t vmi);
void xen_set_domainid(
    vmi_instance_t vmi,
    unsigned long domainid);
status_t xen_check_domainid(
    vmi_instance_t vmi,
    unsigned long domainid);
status_t xen_get_domainname(
    vmi_instance_t vmi,
    char **name);
void xen_set_domainname(
    vmi_instance_t vmi,
    char *name);
status_t xen_get_memsize(
    vmi_instance_t vmi,
    unsigned long *size);
status_t xen_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu);
status_t
xen_set_vcpureg(
    vmi_instance_t vmi,
    reg_t value,
    registers_t reg,
    unsigned long vcpu);
status_t xen_get_address_width(
    vmi_instance_t vmi,
    uint8_t * width_in_bytes);
void *xen_read_page(
    vmi_instance_t vmi,
    addr_t page);
status_t xen_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length);
int xen_is_pv(
    vmi_instance_t vmi);
status_t xen_test(
    unsigned long id,
    char *name);
status_t xen_pause_vm(
    vmi_instance_t vmi);
status_t xen_resume_vm(
    vmi_instance_t vmi);
status_t xen_set_domain_debug_control(
    vmi_instance_t vmi,
    unsigned long vcpu,
    int enable);

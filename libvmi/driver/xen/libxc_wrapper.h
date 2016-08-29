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
#include <xenctrl.h>
#include <dlfcn.h>

#include "libvmi.h"
#include "xen_events_abi.h"

struct xen_instance;

typedef struct {
    void *handle;

    /* Xen 4.1 - Xen 4.5 */
    int (*xc_domain_maximum_gpfn)
            (xc_interface *xch, domid_t domid);

    /* Xen 4.6+ */
    int (*xc_domain_maximum_gpfn2)
            (xc_interface *xch, domid_t domid, xen_pfn_t *gpfns);

    /* Xen 4.1 - Xen 4.4 */
    void* (*xc_map_foreign_batch)
            (xc_interface *xch, uint32_t dom, int prot, xen_pfn_t *arr, int num);

    /* Xen 4.1 - 4.4 */
    int (*xc_hvm_set_mem_access)
            (xc_interface *xch, domid_t dom, hvmmem_access_t memaccess, uint64_t first_pfn, uint64_t nr);

    int (*xc_hvm_get_mem_access)
            (xc_interface *xch, domid_t dom, uint64_t pfn, hvmmem_access_t* memaccess);

    /* Xen 4.5+ */
    int (*xc_set_mem_access)
            (xc_interface *xch, domid_t domain_id, xenmem_access_t access, uint64_t first_pfn, uint32_t nr);

    int (*xc_get_mem_access)
            (xc_interface *xch, domid_t domain_id, uint64_t pfn, xenmem_access_t *access);

    /* Xen 4.1 - Xen 4.4 */
    int (*xc_mem_access_enable)
            (xc_interface *xch, domid_t domain_id, uint32_t *port);

    /* Xen 4.5 */
    void* (*xc_mem_access_enable2)
            (xc_interface *xch, domid_t domain_id, uint32_t *port);

    /* Xen 4.1+ */
    int (*xc_mem_access_disable)
            (xc_interface *xch, domid_t domain_id);

    int (*xc_mem_access_resume)
            (xc_interface *xch, domid_t domain_id);

    /* Xen 4.6+ */
    void* (*xc_monitor_enable)
            (xc_interface *xch, domid_t domain_id, uint32_t *port);

    int (*xc_monitor_disable)
            (xc_interface *xch, domid_t domain_id);

    int (*xc_monitor_resume)
            (xc_interface *xch, domid_t domain_id);

    int (*xc_monitor_get_capabilities)
            (xc_interface *xch, domid_t domain_id, uint32_t *capabilities);

    int (*xc_monitor_write_ctrlreg)
            (xc_interface *xch, domid_t domain_id, uint16_t index, bool enable, bool sync, bool onchangeonly);

    int (*xc_monitor_mov_to_msr)
            (xc_interface *xch, domid_t domain_id, uint32_t msr, bool enable);

    int (*xc_monitor_singlestep)
            (xc_interface *xch, domid_t domain_id, bool enable);

    int (*xc_monitor_software_breakpoint)
            (xc_interface *xch, domid_t domain_id, bool enable);

    int (*xc_monitor_guest_request)
            (xc_interface *xch, domid_t domain_id, bool enable, bool sync);

    int (*xc_altp2m_set_mem_access)
        (xc_interface *handle, domid_t domid, uint16_t view_id, xen_pfn_t gfn, xenmem_access_t access);

    /* Xen 4.8+ */
    int (*xc_monitor_debug_exceptions)
            (xc_interface *xch, domid_t domain_id, bool enable, bool sync);

    int (*xc_monitor_cpuid)
            (xc_interface *xch, domid_t domain_id, bool enable);

} libxc_wrapper_t;

status_t create_libxc_wrapper(struct xen_instance *xen);

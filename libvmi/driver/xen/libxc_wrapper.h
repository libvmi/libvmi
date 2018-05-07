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
typedef int xc_evtchn_port_or_error_t;

typedef struct {
    void *handle;

    /* Xen 4.1+ */
    xc_interface* (*xc_interface_open)
    (xentoollog_logger *logger, xentoollog_logger *dombuild_logger, unsigned open_flags);

    int (*xc_interface_close)
    (xc_interface *xch);

    int (*xc_version)
    (xc_interface *xch, int cmd, void *arg);

    void* (*xc_map_foreign_range)
    (xc_interface *xch, uint32_t domid, int size, int prot, unsigned long mfn );

    int (*xc_vcpu_getcontext)
    (xc_interface *xch, uint32_t domid, uint32_t vcpu, vcpu_guest_context_any_t *ctxt);

    int (*xc_vcpu_setcontext)
    (xc_interface *xch, uint32_t domid, uint32_t vcpu, vcpu_guest_context_any_t *ctxt);

    int (*xc_domain_hvm_getcontext)
    (xc_interface *xch, uint32_t domid, uint8_t *ctxt_buf, uint32_t size);

    int (*xc_domain_hvm_setcontext)
    (xc_interface *xch, uint32_t domid, uint8_t *hvm_ctxt, uint32_t size);

    int (*xc_domain_hvm_getcontext_partial)
    (xc_interface *xch, uint32_t domid, uint16_t typecode,
     uint16_t instance, void *ctxt_buf, uint32_t size);

    int (*xc_domain_getinfo)
    (xc_interface *xch, uint32_t first_domid, unsigned int max_doms, xc_dominfo_t *info);

    int (*xc_domctl)
    (xc_interface *xch, struct xen_domctl *domctl);

    int (*xc_domain_pause)
    (xc_interface *xch, uint32_t domid);

    int (*xc_domain_unpause)
    (xc_interface *xch, uint32_t domid);

    /* Xen 4.2+ */
    int (*xc_domain_debug_control)
    (xc_interface *xch, uint32_t domid, uint32_t sop, uint32_t vcpu);

    int (*xc_domain_set_access_required)
    (xc_interface *xch, uint32_t domid, unsigned int required);

    int (*xc_domain_decrease_reservation_exact)
    (xc_interface *xch, uint32_t domid, unsigned long nr_extents,
     unsigned int extent_order, xen_pfn_t *extent_start);

    int (*xc_hvm_inject_trap)
    (xc_interface *xch, domid_t dom, int vcpu, uint32_t vector,
     uint32_t type, uint32_t error_code, uint32_t insn_len, uint64_t cr2);

    int (*xc_domain_getinfolist)
    (xc_interface *xch, uint32_t first_domain, unsigned int max_domains,
     xc_domaininfo_t *info);

    int (*xc_domain_populate_physmap_exact)
    (xc_interface *xch, uint32_t domid, unsigned long nr_extents,
     unsigned int extent_order, unsigned int mem_flags, xen_pfn_t *extent_start);

    xc_evtchn* (*xc_evtchn_open)
    (xentoollog_logger *logger, unsigned open_flags);

    int (*xc_evtchn_close)
    (xc_evtchn *xce);

    int (*xc_evtchn_fd)
    (xc_evtchn *xce);

    int (*xc_evtchn_notify)
    (xc_evtchn *xce, evtchn_port_t port);

    xc_evtchn_port_or_error_t (*xc_evtchn_pending)
    (xc_evtchn *xce);

    int (*xc_evtchn_unmask)
    (xc_evtchn *xce, evtchn_port_t port);

    int (*xc_evtchn_unbind)
    (xc_evtchn *xce, evtchn_port_t port);

    xc_evtchn_port_or_error_t (*xc_evtchn_bind_interdomain)
    (xc_evtchn *xce, int domid, evtchn_port_t remote_port);

    /* Xen 4.1 - Xen 4.5 */
    int (*xc_domain_maximum_gpfn)
    (xc_interface *xch, domid_t domid);

    /* Xen 4.6+ */
    int (*xc_domain_maximum_gpfn2)
    (xc_interface *xch, domid_t domid, xen_pfn_t *gpfns);

    /* Xen 4.1 - Xen 4.4 */
    void* (*xc_map_foreign_batch)
    (xc_interface *xch, uint32_t dom, int prot, xen_pfn_t *arr, int num);

    int (*xc_set_hvm_param)
    (xc_interface *handle, domid_t dom, int param, unsigned long value);

    int (*xc_get_hvm_param)
    (xc_interface *handle, domid_t dom, int param, unsigned long *value);

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

    int (*xc_hvm_param_set)
    (xc_interface *handle, domid_t dom, uint32_t param, uint64_t value);

    int (*xc_hvm_param_get)
    (xc_interface *handle, domid_t dom, uint32_t param, uint64_t *value);

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
    (xc_interface *xch, domid_t domain_id, bool enable, bool extended_capture);

    int (*xc_monitor_singlestep)
    (xc_interface *xch, domid_t domain_id, bool enable);

    int (*xc_monitor_software_breakpoint)
    (xc_interface *xch, domid_t domain_id, bool enable);

    int (*xc_monitor_guest_request)
    (xc_interface *xch, domid_t domain_id, bool enable, bool sync);

    int (*xc_altp2m_get_domain_state)
    (xc_interface *xch, domid_t domain_id, bool *state );

    int (*xc_altp2m_set_domain_state)
    (xc_interface *xch, domid_t domain_id, bool state );

    int (*xc_altp2m_set_vcpu_enable_notify)
    (xc_interface *xch, domid_t domain_id, uint32_t vcpuid, xen_pfn_t gfn );

    int (*xc_altp2m_create_view)
    (xc_interface *xch, domid_t domain_id, xenmem_access_t default_access, uint16_t *view_id );

    int (*xc_altp2m_destroy_view)
    (xc_interface *xch, domid_t domain_id, uint16_t view_id );

    int (*xc_altp2m_switch_to_view)
    (xc_interface *xch, domid_t domain_id, uint16_t view_id );

    int (*xc_altp2m_set_mem_access)
    (xc_interface *xch, domid_t domain_id, uint16_t view_id, xen_pfn_t gfn, xenmem_access_t access);

    int (*xc_altp2m_change_gfn)
    (xc_interface *xch, domid_t domain_id, uint16_t view_id, xen_pfn_t old_gfn, xen_pfn_t new_gfn );

    /* Xen 4.8+ */
    int (*xc_monitor_debug_exceptions)
    (xc_interface *xch, domid_t domain_id, bool enable, bool sync);

    int (*xc_monitor_cpuid)
    (xc_interface *xch, domid_t domain_id, bool enable);

    int (*xc_monitor_mov_to_msr2)
    (xc_interface *xch, domid_t domain_id, uint32_t msr, bool enable);

    int (*xc_domain_cacheflush)
    (xc_interface *xch, uint32_t domid, xen_pfn_t start_pfn, xen_pfn_t nr_pfns);

    int (*xc_monitor_privileged_call)
    (xc_interface *xch, domid_t domain_id, bool enable);

    /* Xen 4.10+ */
    int (*xc_monitor_descriptor_access)
    (xc_interface *xch, domid_t domain_id, bool enable);

    /* Xen 4.11+ */
    int (*xc_monitor_emul_unimplemented)
    (xc_interface *xch, domid_t domain_id, bool enable);

} libxc_wrapper_t;

status_t create_libxc_wrapper(struct xen_instance *xen);

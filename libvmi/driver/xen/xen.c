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

#include "private.h"

#include "driver/xen/xen.h"
#include "driver/xen/xen_private.h"
#include "driver/xen/xen_events.h"
#include "driver/driver_interface.h"
#include "driver/memory_cache.h"
#include "driver/xen/altp2m_private.h"

//----------------------------------------------------------------------------
// Helper functions

//----------------------------------------------------------------------------
// Xen-Specific Interface Functions (no direct mapping to driver_*)

//TODO assuming length == page size is safe for now, but isn't the most clean approach
void *
xen_get_memory_pfn(
    vmi_instance_t vmi,
    addr_t pfn,
    int prot)
{
    xen_instance_t *xen = xen_get_instance(vmi);
    void *memory = xen->libxcw.xc_map_foreign_range(xen->xchandle,
                   xen->domainid,
                   XC_PAGE_SIZE,
                   prot,
                   (unsigned long) pfn);

    if (MAP_FAILED == memory || NULL == memory) {
        dbprint(VMI_DEBUG_XEN, "--xen_get_memory_pfn failed on pfn=0x%"PRIx64"\n", pfn);
        return NULL;
    } else {
        dbprint(VMI_DEBUG_XEN, "--xen_get_memory_pfn success on pfn=0x%"PRIx64"\n", pfn);
    }

#ifdef VMI_DEBUG
    // copy memory to local address space - handy for examination
    uint8_t buf[XC_PAGE_SIZE];

    memcpy(buf, memory, XC_PAGE_SIZE);
#endif // VMI_DEBUG

    return memory;
}

void *
xen_get_memory(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t UNUSED(length))
{
    //TODO assuming length == page size is safe for now, but isn't the most clean approach
    addr_t pfn = paddr >> vmi->page_shift;

    return xen_get_memory_pfn(vmi, pfn, PROT_READ);
}

void
xen_release_memory(
    void *memory,
    size_t length)
{
    munmap(memory, length);
}

status_t
xen_put_memory(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t count,
    void *buf)
{
    unsigned char *memory = NULL;
    addr_t phys_address = 0;
    addr_t pfn = 0;
    addr_t offset = 0;
    size_t buf_offset = 0;

#if defined(ARM32) || defined(ARM64)
    xen_instance_t *xen = xen_get_instance(vmi);
#endif

    while (count > 0) {
        size_t write_len = 0;

        /* access the memory */
        phys_address = paddr + buf_offset;
        pfn = phys_address >> vmi->page_shift;
        offset = (vmi->page_size - 1) & phys_address;
        memory = xen_get_memory_pfn(vmi, pfn, PROT_WRITE);
        if (NULL == memory) {
            return VMI_FAILURE;
        }

        /* determine how much we can write */
        if ((offset + count) > vmi->page_size) {
            write_len = vmi->page_size - offset;
        } else {
            write_len = count;
        }

        /*
         * The ARM architecture doesn't provide cache coherence guarantees.
         * To ensure that the CPUs won't use stale data we need to flush
         * the l1&l2 cache manually.
         * Prior to Xen 4.9 xc_domain_cacheflush only flushes the data caches.
         * As such, if the modification is made to code that is actively in use,
         * the CPUs may still execute stale instructions afterwards.
         */
#if defined(ARM32) || defined(ARM64)
        xen_pause_vm(vmi);
#endif

        /* do the write */
        memcpy(memory + offset, ((char *) buf) + buf_offset, write_len);

#if defined(ARM32) || defined(ARM64)
        xen->libxcw.xc_domain_cacheflush(xen->xchandle, xen->domainid, pfn, 1);
        xen_resume_vm(vmi);
#endif

        /*
         * We need to refresh the page cache after a page is written to
         * because it might have had been a copy-on-write page. After this
         * write the mapping changes but the cached reference is to the
         * old (origin) page.
         */
        memory_cache_remove(vmi, (phys_address >> vmi->page_shift) << vmi->page_shift);

        /* set variables for next loop */
        count -= write_len;
        buf_offset += write_len;
        xen_release_memory(memory, vmi->page_size);
    }

    return VMI_SUCCESS;
}



//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

/*
 * This function is only usable with xenstore
 * formerly vmi_get_domain_id
 */
#ifndef HAVE_LIBXENSTORE
uint64_t xen_get_domainid_from_name(
    vmi_instance_t UNUSED(vmi),
    const char* UNUSED(name))
{
    return VMI_INVALID_DOMID;
}
#else
uint64_t xen_get_domainid_from_name(
    vmi_instance_t vmi,
    const char *name)
{
    if (name == NULL) {
        return VMI_INVALID_DOMID;
    }

    xen_instance_t *xen = xen_get_instance(vmi);
    char **domains = NULL;
    unsigned int size = 0, i = 0;
    xs_transaction_t xth = XBT_NULL;
    uint64_t domainid = VMI_INVALID_DOMID;
    char *tmp;

    struct xs_handle *xsh = xen->libxsw.xs_open(0);

    if (!xsh)
        goto _bail;

    domains = xen->libxsw.xs_directory(xsh, xth, "/local/domain", &size);
    for (i = 0; i < size; ++i) {
        /* read in name */
        char *idStr = domains[i];

        tmp = g_malloc0(snprintf(NULL, 0, "/local/domain/%s/name", idStr)+1);
        sprintf(tmp, "/local/domain/%s/name", idStr);
        char *nameCandidate = xen->libxsw.xs_read(xsh, xth, tmp, NULL);
        free(tmp);

        // if name matches, then return number
        if (nameCandidate != NULL &&
                strncmp(name, nameCandidate, 100) == 0) {
            domainid = strtoull(idStr, NULL, 0);
            free(nameCandidate);
            break;
        }

        /* free memory as we go */
        if (nameCandidate)
            free(nameCandidate);

    }

_bail:
    if (domains)
        free(domains);
    if (xsh)
        xen->libxsw.xs_close(xsh);
    return domainid;
}
#endif

/*
 * This function is only usable with xenstore
 */
#ifndef HAVE_LIBXENSTORE
status_t xen_get_name_from_domainid(
    vmi_instance_t UNUSED(vmi),
    uint64_t UNUSED(domainid),
    char** UNUSED(name))
{
    return VMI_FAILURE;
}
#else
status_t xen_get_name_from_domainid(
    vmi_instance_t vmi,
    uint64_t domainid,
    char** name)
{
    status_t ret = VMI_FAILURE;
    if (domainid == VMI_INVALID_DOMID) {
        return ret;
    }

    xen_instance_t *xen = xen_get_instance(vmi);
    xs_transaction_t xth = XBT_NULL;

    struct xs_handle *xsh = xen->libxsw.xs_open(0);

    if (!xsh)
        goto _bail;

    char *tmp = g_malloc0(snprintf(NULL, 0, "/local/domain/%"PRIu64"/name", domainid)+1);
    sprintf(tmp, "/local/domain/%"PRIu64"/name", domainid);
    char *nameCandidate = xen->libxsw.xs_read(xsh, xth, tmp, NULL);
    free(tmp);

    if (nameCandidate != NULL) {
        *name = nameCandidate;
        ret = VMI_SUCCESS;
    }

_bail:
    if (xsh)
        xen->libxsw.xs_close(xsh);
    return ret;
}
#endif

uint64_t
xen_get_domainid(
    vmi_instance_t vmi)
{
    return xen_get_instance(vmi)->domainid;
}

void
xen_set_domainid(
    vmi_instance_t vmi,
    uint64_t domainid)
{
    xen_get_instance(vmi)->domainid = domainid;
}

status_t
xen_check_domainid(
    vmi_instance_t vmi,
    uint64_t domainid)
{
    status_t ret = VMI_FAILURE;
    xc_dominfo_t info;
    domid_t max_domid = ~0;
    int rc;
    xen_instance_t *xen = NULL;

    if ( domainid > max_domid ) {
        dbprint(VMI_DEBUG_XEN,"Domain ID is invalid, larger then the max supported on Xen!\n");
        return ret;
    }

    xen = xen_get_instance(vmi);

    rc = xen->libxcw.xc_domain_getinfo(xen->xchandle, domainid, 1, &info);

    if (rc==1 && info.domid==(uint32_t)domainid)
        ret = VMI_SUCCESS;
    else
        xen_destroy(vmi);

    return ret;
}

static inline status_t
xen_discover_pv_type(
    vmi_instance_t vmi)
{
    status_t ret = VMI_SUCCESS;

    /* Only for x86 */
#if defined(I386) || defined(X86_64)

    xen_instance_t *xen = xen_get_instance(vmi);
    int rc;
    xen_domctl_t domctl = { 0 };

    domctl.domain = xen->domainid;

    // TODO: test this on a 32-bit PV guest
    // Note: it appears that this DOMCTL does not wok on an HVM
    domctl.cmd = XEN_DOMCTL_get_address_size;

    // This DOMCTL always returns 0 (Xen 4.1.2)
    //domctl.cmd    = XEN_DOMCTL_get_machine_address_size;

    rc = xen->libxcw.xc_domctl(xen->xchandle, &domctl);
    if (rc) {
        errprint("Failed to get domain address width (#1), value retrieved %d\n",
                 domctl.u.address_size.size);
        goto _bail;
    }   // if

    // translate width to bytes from bits
    uint32_t addr_width = domctl.u.address_size.size / 8;
    dbprint(VMI_DEBUG_XEN, "**guest address width is %d bytes\n", addr_width);

    switch (addr_width) {
        case 8:
            vmi->vm_type = PV64;
            break;
        case 4:
            vmi->vm_type = PV32;
            break;
        default:
            errprint("Failed to get domain address width (#2), value retrieved %d\n",
                     domctl.u.address_size.size);
            ret = VMI_FAILURE;
            goto _bail;
    };
#endif

_bail:
    return ret;
}

/**
 * Setup xen live mode.
 */
status_t
xen_setup_live_mode(
    vmi_instance_t vmi)
{
    dbprint(VMI_DEBUG_XEN, "--xen: setup live mode\n");
    memory_cache_destroy(vmi);
    memory_cache_init(vmi, xen_get_memory, xen_release_memory, 0);
    return VMI_SUCCESS;
}

status_t
xen_init(
    vmi_instance_t vmi,
    uint32_t UNUSED(init_flags),
    void *UNUSED(init_data))
{
    if ( xen_get_instance(vmi) )
        return VMI_SUCCESS;

    xen_instance_t *xen = g_malloc0(sizeof(xen_instance_t));

    if ( VMI_FAILURE == create_libxc_wrapper(xen) ) {
        dbprint(VMI_DEBUG_XEN, "Failed to find a suitable xenctrl.so!\n");
        g_free(xen);
        return VMI_FAILURE;
    }

    /* initialize other xen-specific values */
#ifdef HAVE_LIBXENSTORE
    if ( VMI_FAILURE == create_libxs_wrapper(xen) ) {
        dbprint(VMI_DEBUG_XEN, "Failed to find a suitable xenstore.so!\n");
        xen->libxcw.xc_interface_close(xen->xchandle);
        g_free(xen);
        return VMI_FAILURE;
    }

    xen->xshandle = xen->libxsw.xs_open(0);
    if (!xen->xshandle) {
        errprint("xs_domain_open failed\n");
        xen->libxcw.xc_interface_close(xen->xchandle);
        g_free(xen);
        return VMI_FAILURE;
    }
#endif

    vmi->driver.driver_data = (void *)xen;
    return VMI_SUCCESS;
}

status_t
xen_init_vmi(
    vmi_instance_t vmi,
    uint32_t init_flags,
    void *init_data)
{
    status_t ret = VMI_FAILURE;
    xen_instance_t *xen = xen_get_instance(vmi);
    int rc;

    /* setup the info struct */
    rc = xen->libxcw.xc_domain_getinfo(xen->xchandle,
                                       xen->domainid,
                                       1,
                                       &xen->info);
    if (rc != 1) {
        errprint("Failed to get domain info for Xen.\n");
        goto _bail;
    }

    /* record the count of VCPUs used by this instance */
    vmi->num_vcpus = xen->info.max_vcpu_id + 1;

    /* determine if target is hvm or pv */
    if ( xen->info.hvm ) {
        vmi->vm_type = HVM;
    } else if ( VMI_FAILURE == xen_discover_pv_type(vmi) ) {
        errprint("Failed to determine PV type for Xen.\n");
        goto _bail;
    }

    if ( vmi->vm_type == HVM )
        dbprint(VMI_DEBUG_XEN, "**set vm_type HVM\n");
    if ( vmi->vm_type == PV32 )
        dbprint(VMI_DEBUG_XEN, "**set vm_type PV32\n");
    if ( vmi->vm_type == PV64 )
        dbprint(VMI_DEBUG_XEN, "**set vm_type PV64\n");

    if ( xen->major_version == 4 && xen->minor_version < 6 )
        xen->max_gpfn = (uint64_t)xen->libxcw.xc_domain_maximum_gpfn(xen->xchandle, xen->domainid);
    else if (xen->libxcw.xc_domain_maximum_gpfn2(xen->xchandle, xen->domainid, (xen_pfn_t*)&xen->max_gpfn)) {
        errprint("Failed to get max gpfn for Xen.\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    if (xen->max_gpfn <= 0) {
        errprint("Failed to get max gpfn for Xen.\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    /* For Xen PV domains, where xc_domain_maximum_gpfn() returns a number
     * more like nr_pages, which is usually less than max_pages or the
     * calculated number of pages based on memkb, just fake it to be sane. */
    if ((xen->max_gpfn << 12) < (xen->info.max_memkb * 1024)) {
        xen->max_gpfn = (xen->info.max_memkb * 1024) >> 12;
    }

    ret = xen_setup_live_mode(vmi);

    if ( VMI_FAILURE == ret )
        goto _bail;

    if (vmi->vm_type == HVM && (vmi->init_flags & VMI_INIT_EVENTS)) {
        ret = xen_init_events(vmi, init_flags, init_data);

        if ( VMI_FAILURE == ret )
            goto _bail;
    }

    xen_init_altp2m(vmi);

_bail:
    return ret;
}

void
xen_destroy(
    vmi_instance_t vmi)
{
    xen_instance_t *xen = xen_get_instance(vmi);

    if (!xen) return;

    if (vmi->vm_type == HVM && (vmi->init_flags & VMI_INIT_EVENTS))
        xen_events_destroy(vmi);

    xc_interface *xchandle = xen_get_xchandle(vmi);
    if ( xchandle )
        xen->libxcw.xc_interface_close(xchandle);

    dlclose(xen->libxcw.handle);

#ifdef HAVE_LIBXENSTORE
    if (xen->xshandle) {
        xen->libxsw.xs_close(xen->xshandle);
    }

    dlclose(xen->libxsw.handle);
#endif

    g_free(xen->name);
    g_free(xen);

    vmi->driver.driver_data = NULL;
}

/*
 * This function is only usable with Xenstore
 */
status_t
xen_get_domainname(
#ifndef HAVE_LIBXENSTORE
    vmi_instance_t UNUSED(vmi),
    char** UNUSED(name))
{
    return VMI_FAILURE;
}
#else
    vmi_instance_t vmi,
    char** name)
{
    status_t ret = VMI_FAILURE;
    xs_transaction_t xth = XBT_NULL;
    xen_instance_t *xen = xen_get_instance(vmi);

    if (!xen->xshandle) {
        errprint("Couldn't get Xenstore handle!\n");
        goto _bail;
    }

    char *tmp = g_malloc0(snprintf(NULL,
                                   0,
                                   "/local/domain/%"PRIu64"/name",
                                   xen->domainid)
                          +1);
    sprintf(tmp, "/local/domain/%"PRIu64"/name", xen->domainid);
    *name = xen->libxsw.xs_read(xen->xshandle, xth, tmp, NULL);
    free(tmp);

    if (*name == NULL) {
        errprint("Couldn't get name of domain %"PRIu64" from Xenstore\n", xen->domainid);
        goto _bail;
    }
    ret = VMI_SUCCESS;

_bail:
    return ret;
}
#endif

void xen_set_domainname(
    vmi_instance_t vmi,
    const char *name)
{
    xen_get_instance(vmi)->name = strndup(name, 500);
}

status_t
xen_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *max_physical_address)
{
    // note: may also available through xen_get_instance(vmi)->info.max_memkb
    // or xenstore /local/domain/%d/memory/target
    uint64_t pages = xen_get_instance(vmi)->info.nr_pages + xen_get_instance(vmi)->info.nr_shared_pages;

    if (pages == 0) {
        return VMI_FAILURE;
    }

    *allocated_ram_size = XC_PAGE_SIZE * pages;

    addr_t max_gpfn = xen_get_instance(vmi)->max_gpfn;
    if (max_gpfn == 0) {
        return VMI_FAILURE;
    }

    *max_physical_address = max_gpfn * XC_PAGE_SIZE;

    return VMI_SUCCESS;
}

#if defined(I386) || defined(X86_64)
static status_t
xen_get_vcpureg_hvm(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
    status_t ret = VMI_SUCCESS;
    struct hvm_hw_cpu* hvm_cpu = NULL;
    xen_instance_t *xen = xen_get_instance(vmi);

    struct hvm_hw_cpu hw_ctxt;
    if (NULL == hvm_cpu) {
        if (xen->libxcw.xc_domain_hvm_getcontext_partial(xen->xchandle,
                xen->domainid,
                HVM_SAVE_CODE(CPU),
                vcpu,
                &hw_ctxt,
                sizeof hw_ctxt)) {
            errprint("Failed to get context information (HVM domain).\n");
            ret = VMI_FAILURE;
            goto _bail;
        }
        hvm_cpu = &hw_ctxt;
    }

    switch (reg) {
        case RAX:
            *value = (reg_t) hvm_cpu->rax;
            break;
        case RBX:
            *value = (reg_t) hvm_cpu->rbx;
            break;
        case RCX:
            *value = (reg_t) hvm_cpu->rcx;
            break;
        case RDX:
            *value = (reg_t) hvm_cpu->rdx;
            break;
        case RBP:
            *value = (reg_t) hvm_cpu->rbp;
            break;
        case RSI:
            *value = (reg_t) hvm_cpu->rsi;
            break;
        case RDI:
            *value = (reg_t) hvm_cpu->rdi;
            break;
        case RSP:
            *value = (reg_t) hvm_cpu->rsp;
            break;
        case R8:
            *value = (reg_t) hvm_cpu->r8;
            break;
        case R9:
            *value = (reg_t) hvm_cpu->r9;
            break;
        case R10:
            *value = (reg_t) hvm_cpu->r10;
            break;
        case R11:
            *value = (reg_t) hvm_cpu->r11;
            break;
        case R12:
            *value = (reg_t) hvm_cpu->r12;
            break;
        case R13:
            *value = (reg_t) hvm_cpu->r13;
            break;
        case R14:
            *value = (reg_t) hvm_cpu->r14;
            break;
        case R15:
            *value = (reg_t) hvm_cpu->r15;
            break;
        case RIP:
            *value = (reg_t) hvm_cpu->rip;
            break;
        case RFLAGS:
            *value = (reg_t) hvm_cpu->rflags;
            break;

        case CR0:
            *value = (reg_t) hvm_cpu->cr0;
            break;
        case CR2:
            *value = (reg_t) hvm_cpu->cr2;
            break;
        case CR3:
            *value = (reg_t) hvm_cpu->cr3;
            break;
        case CR4:
            *value = (reg_t) hvm_cpu->cr4;
            break;

        case DR0:
            *value = (reg_t) hvm_cpu->dr0;
            break;
        case DR1:
            *value = (reg_t) hvm_cpu->dr1;
            break;
        case DR2:
            *value = (reg_t) hvm_cpu->dr2;
            break;
        case DR3:
            *value = (reg_t) hvm_cpu->dr3;
            break;
        case DR6:
            *value = (reg_t) hvm_cpu->dr6;
            break;
        case DR7:
            *value = (reg_t) hvm_cpu->dr7;
            break;

        case CS_SEL:
            *value = (reg_t) hvm_cpu->cs_sel;
            break;
        case DS_SEL:
            *value = (reg_t) hvm_cpu->ds_sel;
            break;
        case ES_SEL:
            *value = (reg_t) hvm_cpu->es_sel;
            break;
        case FS_SEL:
            *value = (reg_t) hvm_cpu->fs_sel;
            break;
        case GS_SEL:
            *value = (reg_t) hvm_cpu->gs_sel;
            break;
        case SS_SEL:
            *value = (reg_t) hvm_cpu->ss_sel;
            break;
        case TR_SEL:
            *value = (reg_t) hvm_cpu->tr_sel;
            break;
        case LDTR_SEL:
            *value = (reg_t) hvm_cpu->ldtr_sel;
            break;

        case CS_LIMIT:
            *value = (reg_t) hvm_cpu->cs_limit;
            break;
        case DS_LIMIT:
            *value = (reg_t) hvm_cpu->ds_limit;
            break;
        case ES_LIMIT:
            *value = (reg_t) hvm_cpu->es_limit;
            break;
        case FS_LIMIT:
            *value = (reg_t) hvm_cpu->fs_limit;
            break;
        case GS_LIMIT:
            *value = (reg_t) hvm_cpu->gs_limit;
            break;
        case SS_LIMIT:
            *value = (reg_t) hvm_cpu->ss_limit;
            break;
        case TR_LIMIT:
            *value = (reg_t) hvm_cpu->tr_limit;
            break;
        case LDTR_LIMIT:
            *value = (reg_t) hvm_cpu->ldtr_limit;
            break;
        case IDTR_LIMIT:
            *value = (reg_t) hvm_cpu->idtr_limit;
            break;
        case GDTR_LIMIT:
            *value = (reg_t) hvm_cpu->gdtr_limit;
            break;

        case CS_BASE:
            *value = (reg_t) hvm_cpu->cs_base;
            break;
        case DS_BASE:
            *value = (reg_t) hvm_cpu->ds_base;
            break;
        case ES_BASE:
            *value = (reg_t) hvm_cpu->es_base;
            break;
        case FS_BASE:
            *value = (reg_t) hvm_cpu->fs_base;
            break;
        case GS_BASE:
            *value = (reg_t) hvm_cpu->gs_base;
            break;
        case SS_BASE:
            *value = (reg_t) hvm_cpu->ss_base;
            break;
        case TR_BASE:
            *value = (reg_t) hvm_cpu->tr_base;
            break;
        case LDTR_BASE:
            *value = (reg_t) hvm_cpu->ldtr_base;
            break;
        case IDTR_BASE:
            *value = (reg_t) hvm_cpu->idtr_base;
            break;
        case GDTR_BASE:
            *value = (reg_t) hvm_cpu->gdtr_base;
            break;

        case CS_ARBYTES:
            *value = (reg_t) hvm_cpu->cs_arbytes;
            break;
        case DS_ARBYTES:
            *value = (reg_t) hvm_cpu->ds_arbytes;
            break;
        case ES_ARBYTES:
            *value = (reg_t) hvm_cpu->es_arbytes;
            break;
        case FS_ARBYTES:
            *value = (reg_t) hvm_cpu->fs_arbytes;
            break;
        case GS_ARBYTES:
            *value = (reg_t) hvm_cpu->gs_arbytes;
            break;
        case SS_ARBYTES:
            *value = (reg_t) hvm_cpu->ss_arbytes;
            break;
        case TR_ARBYTES:
            *value = (reg_t) hvm_cpu->tr_arbytes;
            break;
        case LDTR_ARBYTES:
            *value = (reg_t) hvm_cpu->ldtr_arbytes;
            break;

        case SYSENTER_CS:
            *value = (reg_t) hvm_cpu->sysenter_cs;
            break;
        case SYSENTER_ESP:
            *value = (reg_t) hvm_cpu->sysenter_esp;
            break;
        case SYSENTER_EIP:
            *value = (reg_t) hvm_cpu->sysenter_eip;
            break;
        case SHADOW_GS:
            *value = (reg_t) hvm_cpu->shadow_gs;
            break;

        case MSR_FLAGS:
            *value = (reg_t) hvm_cpu->msr_flags;
            break;
        case MSR_LSTAR:
            *value = (reg_t) hvm_cpu->msr_lstar;
            break;
        case MSR_CSTAR:
            *value = (reg_t) hvm_cpu->msr_cstar;
            break;
        case MSR_SYSCALL_MASK:
            *value = (reg_t) hvm_cpu->msr_syscall_mask;
            break;
        case MSR_EFER:
            *value = (reg_t) hvm_cpu->msr_efer;
            break;
        case MSR_STAR:
            *value = (reg_t) hvm_cpu->msr_star;
            break;

#ifdef DECLARE_HVM_SAVE_TYPE_COMPAT
        case MSR_TSC_AUX:
            /* Handle churn in struct hvm_hw_cpu (from xen/hvm/save.h)
             * that would prevent otherwise-compatible Xen 4.0 branches
             * from building.
             *
             * Checking this is less than ideal, but seemingly
             * the cleanest means of accomplishing the necessary check.
             *
             * see http://xenbits.xen.org/hg/xen-4.0-testing.hg/rev/57721c697c46
             */
            *value = (reg_t) hvm_cpu->msr_tsc_aux;
            break;
#endif

        case TSC:
            *value = (reg_t) hvm_cpu->tsc;
            break;
        default:
            ret = VMI_FAILURE;
            break;
    }

_bail:
    return ret;
}

static status_t
xen_get_vcpuregs_hvm(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
    xen_instance_t *xen = xen_get_instance(vmi);
    struct hvm_hw_cpu hw_ctxt = {0}, *hvm_cpu = NULL;

    if (NULL == hvm_cpu) {
        if (xen->libxcw.xc_domain_hvm_getcontext_partial(xen->xchandle,
                xen->domainid,
                HVM_SAVE_CODE(CPU),
                vcpu,
                &hw_ctxt,
                sizeof hw_ctxt)) {
            errprint("Failed to get context information (HVM domain).\n");
            return VMI_FAILURE;
        }
        hvm_cpu = &hw_ctxt;
    }

    regs->x86.rax = hvm_cpu->rax;
    regs->x86.rbx = hvm_cpu->rbx;
    regs->x86.rcx = hvm_cpu->rcx;
    regs->x86.rdx = hvm_cpu->rdx;
    regs->x86.rbp = hvm_cpu->rbp;
    regs->x86.rsi = hvm_cpu->rsi;
    regs->x86.rdi = hvm_cpu->rdi;
    regs->x86.rsp = hvm_cpu->rsp;
    regs->x86.r8 = hvm_cpu->r8;
    regs->x86.r9 = hvm_cpu->r9;
    regs->x86.r10 = hvm_cpu->r10;
    regs->x86.r11 = hvm_cpu->r11;
    regs->x86.r12 = hvm_cpu->r12;
    regs->x86.r13 = hvm_cpu->r13;
    regs->x86.r14 = hvm_cpu->r14;
    regs->x86.r15 = hvm_cpu->r15;
    regs->x86.rip = hvm_cpu->rip;
    regs->x86.rflags = hvm_cpu->rflags;
    regs->x86.cr0 = hvm_cpu->cr0;
    regs->x86.cr2 = hvm_cpu->cr2;
    regs->x86.cr3 = hvm_cpu->cr3;
    regs->x86.cr4 = hvm_cpu->cr4;
    regs->x86.dr7 = hvm_cpu->dr7;
    regs->x86.fs_base = hvm_cpu->fs_base;
    regs->x86.gs_base = hvm_cpu->gs_base;
    regs->x86.cs_arbytes = hvm_cpu->cs_arbytes;
    regs->x86.sysenter_cs = hvm_cpu->sysenter_cs;
    regs->x86.sysenter_esp = hvm_cpu->sysenter_esp;
    regs->x86.sysenter_eip = hvm_cpu->sysenter_eip;
    regs->x86.msr_efer = hvm_cpu->msr_efer;
    regs->x86.msr_star = hvm_cpu->msr_star;
    regs->x86.msr_lstar = hvm_cpu->msr_lstar;

    return VMI_SUCCESS;
}

static status_t
xen_set_vcpureg_hvm(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu)
{
    uint32_t size = 0;
    uint32_t off = 0;
    uint8_t *buf = NULL;
    status_t ret = VMI_SUCCESS;
    HVM_SAVE_TYPE(CPU) *cpu = NULL;
    struct hvm_save_descriptor *desc = NULL;
    xen_instance_t *xen = xen_get_instance(vmi);

    /* calling with no arguments --> return is the size of buffer required
     *  for storing the HVM context
     */
    size = xen->libxcw.xc_domain_hvm_getcontext(xen->xchandle,xen->domainid, 0, 0);

    if (size <= 0) {
        errprint("Failed to fetch HVM context buffer size.\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    buf = malloc(size);
    if (buf == NULL) {
        errprint("Failed to allocate HVM context buffer.\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    /* Locate runtime CPU registers in the context record, using the full
     *  version of xc_domain_hvm_getcontext rather than the partial
     *  variant, because there is no equivalent setcontext_partial.
     * NOTE: to avoid inducing race conditions/errors, run while VM is paused.
     */
    if (xen->libxcw.xc_domain_hvm_getcontext(xen->xchandle,
            xen->domainid,
            buf, size) < 0) {
        errprint("Failed to fetch HVM context buffer.\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    off = 0;
    while (off < size) {
        desc = (struct hvm_save_descriptor *)(buf + off);

        off += sizeof (struct hvm_save_descriptor);

        if (desc->typecode == HVM_SAVE_CODE(CPU) && desc->instance == vcpu) {
            cpu = (HVM_SAVE_TYPE(CPU) *)(buf + off);
            break;
        }

        off += desc->length;
    }

    if (cpu == NULL) {
        errprint("Failed to locate HVM cpu context.\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    switch (reg) {
        case RAX:
            cpu->rax = value;
            break;
        case RBX:
            cpu->rbx = value;
            break;
        case RCX:
            cpu->rcx = value;
            break;
        case RDX:
            cpu->rdx = value;
            break;
        case RBP:
            cpu->rbp = value;
            break;
        case RSI:
            cpu->rsi = value;
            break;
        case RDI:
            cpu->rdi = value;
            break;
        case RSP:
            cpu->rsp = value;
            break;
        case R8:
            cpu->r8 = value;
            break;
        case R9:
            cpu->r9 = value;
            break;
        case R10:
            cpu->r10 = value;
            break;
        case R11:
            cpu->r11 = value;
            break;
        case R12:
            cpu->r12 = value;
            break;
        case R13:
            cpu->r13 = value;
            break;
        case R14:
            cpu->r14 = value;
            break;
        case R15:
            cpu->r15 = value;
            break;
        case RIP:
            cpu->rip = value;
            break;
        case RFLAGS:
            cpu->rflags = value;
            break;

        case CR0:
            cpu->cr0 = value;
            break;
        case CR2:
            cpu->cr2 = value;
            break;
        case CR3:
            cpu->cr3 = value;
            break;
        case CR4:
            cpu->cr4 = value;
            break;

        case DR0:
            cpu->dr0 = value;
            break;
        case DR1:
            cpu->dr1 = value;
            break;
        case DR2:
            cpu->dr2 = value;
            break;
        case DR3:
            cpu->dr3 = value;
            break;
        case DR6:
            cpu->dr6 = value;
            break;
        case DR7:
            cpu->dr7 = value;
            break;

        case CS_SEL:
            cpu->cs_sel = value;
            break;
        case DS_SEL:
            cpu->ds_sel = value;
            break;
        case ES_SEL:
            cpu->es_sel = value;
            break;
        case FS_SEL:
            cpu->fs_sel = value;
            break;
        case GS_SEL:
            cpu->gs_sel = value;
            break;
        case SS_SEL:
            cpu->ss_sel = value;
            break;
        case TR_SEL:
            cpu->tr_sel = value;
            break;
        case LDTR_SEL:
            cpu->ldtr_sel = value;
            break;

        case CS_LIMIT:
            cpu->cs_limit = value;
            break;
        case DS_LIMIT:
            cpu->ds_limit = value;
            break;
        case ES_LIMIT:
            cpu->es_limit = value;
            break;
        case FS_LIMIT:
            cpu->fs_limit = value;
            break;
        case GS_LIMIT:
            cpu->gs_limit = value;
            break;
        case SS_LIMIT:
            cpu->ss_limit = value;
            break;
        case TR_LIMIT:
            cpu->tr_limit = value;
            break;
        case LDTR_LIMIT:
            cpu->ldtr_limit = value;
            break;
        case IDTR_LIMIT:
            cpu->idtr_limit = value;
            break;
        case GDTR_LIMIT:
            cpu->gdtr_limit = value;
            break;

        case CS_BASE:
            cpu->cs_base = value;
            break;
        case DS_BASE:
            cpu->ds_base = value;
            break;
        case ES_BASE:
            cpu->es_base = value;
            break;
        case FS_BASE:
            cpu->fs_base = value;
            break;
        case GS_BASE:
            cpu->gs_base = value;
            break;
        case SS_BASE:
            cpu->ss_base = value;
            break;
        case TR_BASE:
            cpu->tr_base = value;
            break;
        case LDTR_BASE:
            cpu->ldtr_base = value;
            break;
        case IDTR_BASE:
            cpu->idtr_base = value;
            break;
        case GDTR_BASE:
            cpu->gdtr_base = value;
            break;

        case CS_ARBYTES:
            cpu->cs_arbytes = value;
            break;
        case DS_ARBYTES:
            cpu->ds_arbytes = value;
            break;
        case ES_ARBYTES:
            cpu->es_arbytes = value;
            break;
        case FS_ARBYTES:
            cpu->fs_arbytes = value;
            break;
        case GS_ARBYTES:
            cpu->gs_arbytes = value;
            break;
        case SS_ARBYTES:
            cpu->ss_arbytes = value;
            break;
        case TR_ARBYTES:
            cpu->tr_arbytes = value;
            break;
        case LDTR_ARBYTES:
            cpu->ldtr_arbytes = value;
            break;

        case SYSENTER_CS:
            cpu->sysenter_cs = value;
            break;
        case SYSENTER_ESP:
            cpu->sysenter_esp = value;
            break;
        case SYSENTER_EIP:
            cpu->sysenter_eip = value;
            break;
        case SHADOW_GS:
            cpu->shadow_gs = value;
            break;

        case MSR_FLAGS:
            cpu->msr_flags = value;
            break;
        case MSR_LSTAR:
            cpu->msr_lstar = value;
            break;
        case MSR_CSTAR:
            cpu->msr_cstar = value;
            break;
        case MSR_SYSCALL_MASK:
            cpu->msr_syscall_mask = value;
            break;
        case MSR_EFER:
            cpu->msr_efer = value;
            break;
        case MSR_STAR:
            cpu->msr_star = value;
            break;

#ifdef DECLARE_HVM_SAVE_TYPE_COMPAT
        case MSR_TSC_AUX:
            /* Handle churn in struct hvm_hw_cpu (from xen/hvm/save.h)
             * that would prevent otherwise-compatible Xen 4.0 branches
             * from building.
             *
             * Checking this is less than ideal, but seemingly
             * the cleanest means of accomplishing the necessary check.
             *
             * see http://xenbits.xen.org/hg/xen-4.0-testing.hg/rev/57721c697c46
             */
            cpu->msr_tsc_aux = value;
            break;
#endif

        case TSC:
            cpu->tsc = value;
            break;
        default:
            ret = VMI_FAILURE;
            break;
    }

    if (xen->libxcw.xc_domain_hvm_setcontext(xen->xchandle, xen->domainid, buf, size)) {
        errprint("Failed to set context information (HVM domain).\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

_bail:

    free(buf);

    return ret;
}

static status_t
xen_set_vcpuregs_hvm(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
    uint32_t size = 0;
    uint32_t off = 0;
    uint8_t *buf = NULL;
    status_t ret = VMI_SUCCESS;
    HVM_SAVE_TYPE(CPU) *cpu = NULL;
    struct hvm_save_descriptor *desc = NULL;
    xen_instance_t *xen = xen_get_instance(vmi);

    /* calling with no arguments --> return is the size of buffer required
     *  for storing the HVM context
     */
    size = xen->libxcw.xc_domain_hvm_getcontext(xen->xchandle,
            xen->domainid, 0, 0);

    if (size <= 0) {
        errprint("Failed to fetch HVM context buffer size.\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    buf = malloc(size);
    if (buf == NULL) {
        errprint("Failed to allocate HVM context buffer.\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    /* Locate runtime CPU registers in the context record, using the full
     *  version of xc_domain_hvm_getcontext rather than the partial
     *  variant, because there is no equivalent setcontext_partial.
     * NOTE: to avoid inducing race conditions/errors, run while VM is paused.
     */
    if (xen->libxcw.xc_domain_hvm_getcontext(xen->xchandle, xen->domainid,
            buf, size) < 0) {
        errprint("Failed to fetch HVM context buffer.\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    off = 0;
    while (off < size) {
        desc = (struct hvm_save_descriptor *)(buf + off);

        off += sizeof (struct hvm_save_descriptor);

        if (desc->typecode == HVM_SAVE_CODE(CPU) && desc->instance == vcpu) {
            cpu = (HVM_SAVE_TYPE(CPU) *)(buf + off);
            break;
        }

        off += desc->length;
    }

    if (cpu == NULL) {
        errprint("Failed to locate HVM cpu context.\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    cpu->rax = regs->x86.rax;
    cpu->rbx = regs->x86.rbx;
    cpu->rcx = regs->x86.rcx;
    cpu->rdx = regs->x86.rdx;
    cpu->rbp = regs->x86.rbp;
    cpu->rsi = regs->x86.rsi;
    cpu->rdi = regs->x86.rdi;
    cpu->rsp = regs->x86.rsp;
    cpu->r8 = regs->x86.r8;
    cpu->r9 = regs->x86.r9;
    cpu->r10 = regs->x86.r10;
    cpu->r11 = regs->x86.r11;
    cpu->r12 = regs->x86.r12;
    cpu->r13 = regs->x86.r13;
    cpu->r14 = regs->x86.r14;
    cpu->r15 = regs->x86.r15;
    cpu->rflags = regs->x86.rflags;
    cpu->cr0 = regs->x86.cr0;
    cpu->cr2 = regs->x86.cr2;
    cpu->cr3 = regs->x86.cr3;
    cpu->cr4 = regs->x86.cr4;
    cpu->dr7 = regs->x86.dr7;
    cpu->fs_base = regs->x86.fs_base;
    cpu->gs_base = regs->x86.gs_base;
    cpu->cs_arbytes = regs->x86.cs_arbytes;
    cpu->sysenter_cs = regs->x86.sysenter_cs;
    cpu->sysenter_esp = regs->x86.sysenter_esp;
    cpu->sysenter_eip = regs->x86.sysenter_eip;
    cpu->msr_lstar = regs->x86.msr_lstar;
    cpu->msr_efer = regs->x86.msr_efer;
    cpu->msr_star = regs->x86.msr_star;

    if (xen->libxcw.xc_domain_hvm_setcontext(
                xen->xchandle, xen->domainid, buf, size)) {
        errprint("Failed to set context information (HVM domain).\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    ret = VMI_SUCCESS;

_bail:
    free(buf);

    return ret;
}

static status_t
xen_get_vcpureg_pv64(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
    vcpu_guest_context_x86_64_t* vcpu_ctx = NULL;
    vcpu_guest_context_any_t ctx;
    xen_instance_t *xen = xen_get_instance(vmi);

    if ( !vcpu_ctx ) {
        if (xen->libxcw.xc_vcpu_getcontext(xen->xchandle, xen->domainid, vcpu, &ctx)) {
            errprint("Failed to get context information (PV domain).\n");
            return VMI_FAILURE;
        }

        vcpu_ctx = &ctx.x64;
    }

    switch (reg) {
        case RAX:
            *value = (reg_t) vcpu_ctx->user_regs.rax;
            break;
        case RBX:
            *value = (reg_t) vcpu_ctx->user_regs.rbx;
            break;
        case RCX:
            *value = (reg_t) vcpu_ctx->user_regs.rcx;
            break;
        case RDX:
            *value = (reg_t) vcpu_ctx->user_regs.rdx;
            break;
        case RBP:
            *value = (reg_t) vcpu_ctx->user_regs.rbp;
            break;
        case RSI:
            *value = (reg_t) vcpu_ctx->user_regs.rsi;
            break;
        case RDI:
            *value = (reg_t) vcpu_ctx->user_regs.rdi;
            break;
        case RSP:
            *value = (reg_t) vcpu_ctx->user_regs.rsp;
            break;
        case R8:
            *value = (reg_t) vcpu_ctx->user_regs.r8;
            break;
        case R9:
            *value = (reg_t) vcpu_ctx->user_regs.r9;
            break;
        case R10:
            *value = (reg_t) vcpu_ctx->user_regs.r10;
            break;
        case R11:
            *value = (reg_t) vcpu_ctx->user_regs.r11;
            break;
        case R12:
            *value = (reg_t) vcpu_ctx->user_regs.r12;
            break;
        case R13:
            *value = (reg_t) vcpu_ctx->user_regs.r13;
            break;
        case R14:
            *value = (reg_t) vcpu_ctx->user_regs.r14;
            break;
        case R15:
            *value = (reg_t) vcpu_ctx->user_regs.r15;
            break;

        case RIP:
            *value = (reg_t) vcpu_ctx->user_regs.rip;
            break;
        case RFLAGS:
            *value = (reg_t) vcpu_ctx->user_regs.rflags;
            break;

        case CR0:
            *value = (reg_t) vcpu_ctx->ctrlreg[0];
            break;
        case CR2:
            *value = (reg_t) vcpu_ctx->ctrlreg[2];
            break;
        case CR3:
            *value = (reg_t) vcpu_ctx->ctrlreg[3];
            *value = (reg_t) (xen_cr3_to_pfn_x86_64(*value) << XC_PAGE_SHIFT);
            break;
        case CR4:
            *value = (reg_t) vcpu_ctx->ctrlreg[4];
            break;

        case DR0:
            *value = (reg_t) vcpu_ctx->debugreg[0];
            break;
        case DR1:
            *value = (reg_t) vcpu_ctx->debugreg[1];
            break;
        case DR2:
            *value = (reg_t) vcpu_ctx->debugreg[2];
            break;
        case DR3:
            *value = (reg_t) vcpu_ctx->debugreg[3];
            break;
        case DR6:
            *value = (reg_t) vcpu_ctx->debugreg[6];
            break;
        case DR7:
            *value = (reg_t) vcpu_ctx->debugreg[7];
            break;
        case FS_BASE:
            *value = (reg_t) vcpu_ctx->fs_base;
            break;
        case GS_BASE:  // TODO: distinguish between kernel & user
            *value = (reg_t) vcpu_ctx->gs_base_kernel;
            break;
        case LDTR_BASE:
            *value = (reg_t) vcpu_ctx->ldt_base;
            break;
        default:
            return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

static status_t
xen_set_vcpureg_pv64(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu)
{
    vcpu_guest_context_any_t ctx;
    xen_instance_t *xen = xen_get_instance(vmi);

    if (xen->libxcw.xc_vcpu_getcontext(xen->xchandle, xen->domainid, vcpu, &ctx)) {
        errprint("Failed to get context information (PV domain).\n");
        return VMI_FAILURE;
    }

    switch (reg) {
        case RAX:
            ctx.x64.user_regs.rax = value;
            break;
        case RBX:
            ctx.x64.user_regs.rbx = value;
            break;
        case RCX:
            ctx.x64.user_regs.rcx = value;
            break;
        case RDX:
            ctx.x64.user_regs.rdx = value;
            break;
        case RBP:
            ctx.x64.user_regs.rbp = value;
            break;
        case RSI:
            ctx.x64.user_regs.rsi = value;
            break;
        case RDI:
            ctx.x64.user_regs.rdi = value;
            break;
        case RSP:
            ctx.x64.user_regs.rsp = value;
            break;
        case R8:
            ctx.x64.user_regs.r8 = value;
            break;
        case R9:
            ctx.x64.user_regs.r9 = value;
            break;
        case R10:
            ctx.x64.user_regs.r10 = value;
            break;
        case R11:
            ctx.x64.user_regs.r11 = value;
            break;
        case R12:
            ctx.x64.user_regs.r12 = value;
            break;
        case R13:
            ctx.x64.user_regs.r13 = value;
            break;
        case R14:
            ctx.x64.user_regs.r14 = value;
            break;
        case R15:
            ctx.x64.user_regs.r15 = value;
            break;

        case RIP:
            ctx.x64.user_regs.rip = value;
            break;
        case RFLAGS:
            ctx.x64.user_regs.rflags = value;
            break;

        case CR0:
            ctx.x64.ctrlreg[0] = value;
            break;
        case CR2:
            ctx.x64.ctrlreg[2] = value;
            break;
        case CR3:
            value = xen_pfn_to_cr3_x86_64(value >> XC_PAGE_SHIFT);
            ctx.x64.ctrlreg[3] = value;
            break;
        case CR4:
            ctx.x64.ctrlreg[4] = value;
            break;

        case DR0:
            ctx.x64.debugreg[0] = value;
            break;
        case DR1:
            ctx.x64.debugreg[1] = value;
            break;
        case DR2:
            ctx.x64.debugreg[2] = value;
            break;
        case DR3:
            ctx.x64.debugreg[3] = value;
            break;
        case DR6:
            ctx.x64.debugreg[6] = value;
            break;
        case DR7:
            ctx.x64.debugreg[7] = value;
            break;
        case FS_BASE:
            ctx.x64.fs_base = value;
            break;
        case GS_BASE: // TODO: distinguish between kernel & user
            ctx.x64.gs_base_kernel = value;
            break;
        case LDTR_BASE:
            ctx.x64.ldt_base = value;
            break;
        default:
            return VMI_FAILURE;
    }

    if (xen->libxcw.xc_vcpu_setcontext(xen->xchandle, xen->domainid, vcpu, &ctx)) {
        errprint("Failed to set context information (PV domain).\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

static status_t
xen_get_vcpureg_pv32(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
    vcpu_guest_context_x86_32_t* vcpu_ctx = NULL;
    xen_instance_t *xen = xen_get_instance(vmi);
    vcpu_guest_context_any_t ctx;

    if (NULL == vcpu_ctx) {
        if (xen->libxcw.xc_vcpu_getcontext(xen->xchandle, xen->domainid, vcpu, &ctx)) {
            errprint("Failed to get context information (PV domain).\n");
            return VMI_FAILURE;
        }
        vcpu_ctx = &ctx.x32;
    }

    switch (reg) {
        case RAX:
            *value = (reg_t) vcpu_ctx->user_regs.eax;
            break;
        case RBX:
            *value = (reg_t) vcpu_ctx->user_regs.ebx;
            break;
        case RCX:
            *value = (reg_t) vcpu_ctx->user_regs.ecx;
            break;
        case RDX:
            *value = (reg_t) vcpu_ctx->user_regs.edx;
            break;
        case RBP:
            *value = (reg_t) vcpu_ctx->user_regs.ebp;
            break;
        case RSI:
            *value = (reg_t) vcpu_ctx->user_regs.esi;
            break;
        case RDI:
            *value = (reg_t) vcpu_ctx->user_regs.edi;
            break;
        case RSP:
            *value = (reg_t) vcpu_ctx->user_regs.esp;
            break;

        case RIP:
            *value = (reg_t) vcpu_ctx->user_regs.eip;
            break;
        case RFLAGS:
            *value = (reg_t) vcpu_ctx->user_regs.eflags;
            break;

        case CR0:
            *value = (reg_t) vcpu_ctx->ctrlreg[0];
            break;
        case CR2:
            *value = (reg_t) vcpu_ctx->ctrlreg[2];
            break;
        case CR3:
            *value = (reg_t) vcpu_ctx->ctrlreg[3];
            *value = (reg_t) xen_cr3_to_pfn_x86_32(*value) << XC_PAGE_SHIFT;
            break;
        case CR4:
            *value = (reg_t) vcpu_ctx->ctrlreg[4];
            break;

        case DR0:
            *value = (reg_t) vcpu_ctx->debugreg[0];
            break;
        case DR1:
            *value = (reg_t) vcpu_ctx->debugreg[1];
            break;
        case DR2:
            *value = (reg_t) vcpu_ctx->debugreg[2];
            break;
        case DR3:
            *value = (reg_t) vcpu_ctx->debugreg[3];
            break;
        case DR6:
            *value = (reg_t) vcpu_ctx->debugreg[6];
            break;
        case DR7:
            *value = (reg_t) vcpu_ctx->debugreg[7];
            break;
        case LDTR_BASE:
            *value = (reg_t) vcpu_ctx->ldt_base;
            break;
        default:
            return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

static status_t
xen_set_vcpureg_pv32(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu)
{
    vcpu_guest_context_any_t ctx;
    xen_instance_t *xen = xen_get_instance(vmi);

    if (xen->libxcw.xc_vcpu_getcontext(xen->xchandle, xen->domainid, vcpu, &ctx)) {
        errprint("Failed to get context information (PV domain).\n");
        return VMI_FAILURE;
    }

    switch (reg) {
        case RAX:
            ctx.x32.user_regs.eax = value;
            break;
        case RBX:
            ctx.x32.user_regs.ebx = value;
            break;
        case RCX:
            ctx.x32.user_regs.ecx = value;
            break;
        case RDX:
            ctx.x32.user_regs.edx = value;
            break;
        case RBP:
            ctx.x32.user_regs.ebp = value;
            break;
        case RSI:
            ctx.x32.user_regs.esi = value;
            break;
        case RDI:
            ctx.x32.user_regs.edi = value;
            break;
        case RSP:
            ctx.x32.user_regs.esp = value;
            break;

        case RIP:
            ctx.x32.user_regs.eip = value;
            break;
        case RFLAGS:
            ctx.x32.user_regs.eflags = value;
            break;

        case CR0:
            ctx.x32.ctrlreg[0] = value;
            break;
        case CR2:
            ctx.x32.ctrlreg[2] = value;
            break;
        case CR3:
            value = xen_pfn_to_cr3_x86_32(value >> XC_PAGE_SHIFT);
            ctx.x32.ctrlreg[3] = value;
            break;
        case CR4:
            ctx.x32.ctrlreg[4] = value;
            break;

        case DR0:
            ctx.x32.debugreg[0] = value;
            break;
        case DR1:
            ctx.x32.debugreg[1] = value;
            break;
        case DR2:
            ctx.x32.debugreg[2] = value;
            break;
        case DR3:
            ctx.x32.debugreg[3] = value;
            break;
        case DR6:
            ctx.x32.debugreg[6] = value;
            break;
        case DR7:
            ctx.x32.debugreg[7] = value;
            break;
        case LDTR_BASE:
            ctx.x32.ldt_base = value;
            break;
        default:
            return VMI_FAILURE;
    }

    if (xen->libxcw.xc_vcpu_setcontext(xen->xchandle, xen->domainid, vcpu, &ctx)) {
        errprint("Failed to set context information (PV domain).\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}
#endif

#if defined(ARM32) || defined(ARM64)
static status_t
xen_get_vcpureg_arm(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
    vcpu_guest_context_any_t ctx;
    xen_instance_t *xen = xen_get_instance(vmi);

    if (xen->libxcw.xc_vcpu_getcontext(xen->xchandle, xen->domainid, vcpu, &ctx)) {
        errprint("Failed to get context information (ARM domain).\n");
        return VMI_FAILURE;
    }

    /* Xen overlays 64-bit registers to the 32-bit ones */
    switch (reg) {
        case SCTLR:
            *value = ctx.c.sctlr;
            break;
        case TTBCR:
            *value = ctx.c.ttbcr;
            break;
        case TTBR0:
            *value = ctx.c.ttbr0;
            break;
        case TTBR1:
            *value = ctx.c.ttbr1;
            break;
        case CPSR:
            *value = ctx.c.user_regs.cpsr;
            break;
        case R0:
            *value = ctx.c.user_regs.r0_usr;
            break;
        case R1:
            *value = ctx.c.user_regs.r1_usr;
            break;
        case R2:
            *value = ctx.c.user_regs.r2_usr;
            break;
        case R3:
            *value = ctx.c.user_regs.r3_usr;
            break;
        case R4:
            *value = ctx.c.user_regs.r4_usr;
            break;
        case R5:
            *value = ctx.c.user_regs.r5_usr;
            break;
        case R6:
            *value = ctx.c.user_regs.r6_usr;
            break;
        case R7:
            *value = ctx.c.user_regs.r7_usr;
            break;
        case R8:
            *value = ctx.c.user_regs.r8_usr;
            break;
        case R9:
            *value = ctx.c.user_regs.r9_usr;
            break;
        case R10:
            *value = ctx.c.user_regs.r10_usr;
            break;
        case R11:
            *value = ctx.c.user_regs.r11_usr;
            break;
        case R12:
            *value = ctx.c.user_regs.r12_usr;
            break;
        case SP_USR:
            *value = ctx.c.user_regs.sp_usr;
            break;
        case LR_USR:
            *value = ctx.c.user_regs.lr_usr;
            break;
        case LR_IRQ:
            *value = ctx.c.user_regs.lr_irq;
            break;
        case SP_IRQ:
            *value = ctx.c.user_regs.sp_irq;
            break;
        case LR_SVC:
            *value = ctx.c.user_regs.lr_svc;
            break;
        case SP_SVC:
            *value = ctx.c.user_regs.sp_svc;
            break;
        case LR_ABT:
            *value = ctx.c.user_regs.lr_abt;
            break;
        case SP_ABT:
            *value = ctx.c.user_regs.sp_abt;
            break;
        case LR_UND:
            *value = ctx.c.user_regs.lr_und;
            break;
        case SP_UND:
            *value = ctx.c.user_regs.sp_und;
            break;
        case R8_FIQ:
            *value = ctx.c.user_regs.r8_fiq;
            break;
        case R9_FIQ:
            *value = ctx.c.user_regs.r9_fiq;
            break;
        case R10_FIQ:
            *value = ctx.c.user_regs.r10_fiq;
            break;
        case R11_FIQ:
            *value = ctx.c.user_regs.r11_fiq;
            break;
        case R12_FIQ:
            *value = ctx.c.user_regs.r12_fiq;
            break;
        case SP_FIQ:
            *value = ctx.c.user_regs.sp_fiq;
            break;
        case LR_FIQ:
            *value = ctx.c.user_regs.lr_fiq;
            break;
        case PC:
            *value = ctx.c.user_regs.pc32;
            break;
        case SPSR_SVC:
            *value = ctx.c.user_regs.spsr_svc;
            break;
        case SPSR_FIQ:
            *value = ctx.c.user_regs.spsr_fiq;
            break;
        case SPSR_IRQ:
            *value = ctx.c.user_regs.spsr_irq;
            break;
        case SPSR_UND:
            *value = ctx.c.user_regs.spsr_und;
            break;
        case SPSR_ABT:
            *value = ctx.c.user_regs.spsr_abt;
            break;
        case SP_EL0:
            *value = ctx.c.user_regs.sp_el0;
            break;
        case SP_EL1:
            *value = ctx.c.user_regs.sp_el1;
            break;
        case ELR_EL1:
            *value = ctx.c.user_regs.elr_el1;
            break;
        default:
            return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

static status_t
xen_set_vcpureg_arm(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu)
{
    vcpu_guest_context_any_t ctx;
    xen_instance_t *xen = xen_get_instance(vmi);

    if (xen->libxcw.xc_vcpu_getcontext(xen->xchandle, xen->domainid, vcpu, &ctx)) {
        errprint("Failed to get context information (ARM domain).\n");
        return VMI_FAILURE;
    }

    switch (reg) {
        case SCTLR:
            ctx.c.sctlr = value;
            break;
        case TTBCR:
            ctx.c.ttbcr = value;
            break;
        case TTBR0:
            ctx.c.ttbr0 = value;
            break;
        case TTBR1:
            ctx.c.ttbr1 = value;
            break;
        case R0:
            ctx.c.user_regs.r0_usr = value;
            break;
        case R1:
            ctx.c.user_regs.r1_usr = value;
            break;
        case R2:
            ctx.c.user_regs.r2_usr = value;
            break;
        case R3:
            ctx.c.user_regs.r3_usr = value;
            break;
        case R4:
            ctx.c.user_regs.r4_usr = value;
            break;
        case R5:
            ctx.c.user_regs.r5_usr = value;
            break;
        case R6:
            ctx.c.user_regs.r6_usr = value;
            break;
        case R7:
            ctx.c.user_regs.r7_usr = value;
            break;
        case R8:
            ctx.c.user_regs.r8_usr = value;
            break;
        case R9:
            ctx.c.user_regs.r9_usr = value;
            break;
        case R10:
            ctx.c.user_regs.r10_usr = value;
            break;
        case R11:
            ctx.c.user_regs.r11_usr = value;
            break;
        case R12:
            ctx.c.user_regs.r12_usr = value;
            break;
        case SP_USR:
            ctx.c.user_regs.sp_usr = value;
            break;
        case LR_USR:
            ctx.c.user_regs.lr_usr = value;
            break;
        case LR_IRQ:
            ctx.c.user_regs.lr_irq = value;
            break;
        case SP_IRQ:
            ctx.c.user_regs.sp_irq = value;
            break;
        case LR_SVC:
            ctx.c.user_regs.lr_svc = value;
            break;
        case SP_SVC:
            ctx.c.user_regs.sp_svc = value;
            break;
        case LR_ABT:
            ctx.c.user_regs.lr_abt = value;
            break;
        case SP_ABT:
            ctx.c.user_regs.sp_abt = value;
            break;
        case LR_UND:
            ctx.c.user_regs.lr_und = value;
            break;
        case SP_UND:
            ctx.c.user_regs.sp_und = value;
            break;
        case R8_FIQ:
            ctx.c.user_regs.r8_fiq = value;
            break;
        case R9_FIQ:
            ctx.c.user_regs.r9_fiq = value;
            break;
        case R10_FIQ:
            ctx.c.user_regs.r10_fiq = value;
            break;
        case R11_FIQ:
            ctx.c.user_regs.r11_fiq = value;
            break;
        case R12_FIQ:
            ctx.c.user_regs.r12_fiq = value;
            break;
        case SP_FIQ:
            ctx.c.user_regs.sp_fiq = value;
            break;
        case LR_FIQ:
            ctx.c.user_regs.lr_fiq = value;
            break;
        case PC:
            ctx.c.user_regs.pc32 = value;
            break;
        case SPSR_SVC:
            ctx.c.user_regs.spsr_svc = value;
            break;
        case SPSR_FIQ:
            ctx.c.user_regs.spsr_fiq = value;
            break;
        case SPSR_IRQ:
            ctx.c.user_regs.spsr_irq = value;
            break;
        case SPSR_UND:
            ctx.c.user_regs.spsr_und = value;
            break;
        case SPSR_ABT:
            ctx.c.user_regs.spsr_abt = value;
            break;
        case SP_EL0:
            ctx.c.user_regs.sp_el0 = value;
            break;
        case SP_EL1:
            ctx.c.user_regs.sp_el1 = value;
            break;
        case ELR_EL1:
            ctx.c.user_regs.elr_el1 = value;
            break;
        default:
            return VMI_FAILURE;
    }

    if (xen->libxcw.xc_vcpu_setcontext(xen->xchandle, xen->domainid, vcpu, &ctx)) {
        errprint("Failed to set context information (ARM domain).\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}
#endif

status_t
xen_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
#if defined(ARM32) || defined(ARM64)
    return xen_get_vcpureg_arm(vmi, value, reg, vcpu);
#elif defined(I386) || defined (X86_64)
    if (vmi->vm_type == HVM)
        return xen_get_vcpureg_hvm (vmi, value, reg, vcpu);
    else {
        if (vmi->vm_type == PV64)
            return xen_get_vcpureg_pv64(vmi, value, reg, vcpu);
        else if (vmi->vm_type == PV32)
            return xen_get_vcpureg_pv32(vmi, value, reg, vcpu);
    }

    return VMI_FAILURE;
#endif
}

status_t
xen_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
#if defined(I386) || defined (X86_64)
    if (vmi->vm_type == HVM)
        return xen_get_vcpuregs_hvm(vmi, regs, vcpu);
#endif

    return VMI_FAILURE;
}

status_t
xen_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu)
{
#if defined(ARM32) || defined(ARM64)
    return xen_set_vcpureg_arm(vmi, value, reg, vcpu);
#elif defined(I386) || defined (X86_64)
    if (vmi->vm_type == HVM)
        return xen_set_vcpureg_hvm (vmi, value, reg, vcpu);
    else {
        if (vmi->vm_type == PV64)
            return xen_set_vcpureg_pv64(vmi, value, reg, vcpu);
        else if (vmi->vm_type == PV32)
            return xen_set_vcpureg_pv32(vmi, value, reg, vcpu);
    }

    return VMI_FAILURE;
#endif
}

status_t
xen_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
#if defined(I386) || defined (X86_64)
    if (vmi->vm_type == HVM)
        return xen_set_vcpuregs_hvm(vmi, regs, vcpu);
#endif

    return VMI_FAILURE;
}

void *
xen_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    addr_t paddr = page << vmi->page_shift;

    return memory_cache_insert(vmi, paddr);
}

status_t
xen_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    return xen_put_memory(vmi, paddr, length, buf);
}

int
xen_is_pv(
    vmi_instance_t vmi)
{
    return !(vmi->vm_type == HVM);
}

status_t
xen_test(
    uint64_t domainid,
    const char *name,
    uint64_t UNUSED(init_flags),
    void* UNUSED(init_data))
{
    struct vmi_instance _vmi = {0};
    vmi_instance_t vmi = &_vmi;

    if (domainid == VMI_INVALID_DOMID && name == NULL) {
        errprint("VMI_ERROR: xen_test: domid or name must be specified\n");
        return VMI_FAILURE;
    }

    if ( VMI_FAILURE == xen_init(vmi, 0, NULL) )
        return VMI_FAILURE;

    if (domainid == VMI_INVALID_DOMID) { /* name != NULL */
        domainid = xen_get_domainid_from_name(vmi, name);
        if (domainid == VMI_INVALID_DOMID) {
            xen_destroy(vmi);
            return VMI_FAILURE;
        }
    }

    if ( VMI_FAILURE == xen_check_domainid(vmi, domainid) ) {
        xen_destroy(vmi);
        return VMI_FAILURE;
    }

    xen_destroy(vmi);
    return VMI_SUCCESS;
}

status_t
xen_pause_vm(
    vmi_instance_t vmi)
{
    xen_instance_t *xen = xen_get_instance(vmi);

    xc_dominfo_t info = {0};
    if (-1 == xen->libxcw.xc_domain_getinfo(xen->xchandle,
                                            xen->domainid,
                                            1,
                                            &info)) {
        return VMI_FAILURE;
    }

    if (info.domid != xen_get_instance(vmi)->domainid) {
        return VMI_FAILURE;
    }

    /* Don't pause if it's already paused. */
    if (info.paused) {
        return VMI_SUCCESS;
    }

    if (-1 == xen->libxcw.xc_domain_pause(xen->xchandle,
                                          xen->domainid)) {
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t
xen_resume_vm(
    vmi_instance_t vmi)
{
    xen_instance_t *xen = xen_get_instance(vmi);

    if (-1 == xen->libxcw.xc_domain_unpause(xen->xchandle, xen->domainid)) {
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t
xen_set_domain_debug_control(
    vmi_instance_t vmi,
    unsigned long vcpu,
    int enable)
{
    xen_instance_t *xen = xen_get_instance(vmi);
    uint32_t op = (enable) ?
                  XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON : XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF;

    int rc = xen->libxcw.xc_domain_debug_control(xen->xchandle,
             xen->domainid,
             op, vcpu);

    return (rc == 0) ? VMI_SUCCESS : VMI_FAILURE;
}

status_t
xen_set_access_required(
    vmi_instance_t vmi,
    bool required)
{
    xen_instance_t *xen = xen_get_instance(vmi);
    // Set whether the access listener is required
    int rc = xen->libxcw.xc_domain_set_access_required(xen->xchandle, xen->domainid, required);
    if ( rc < 0 ) {
        errprint("Error %d setting listener required to %d\n", rc, required);
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

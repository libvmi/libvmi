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

#include "libvmi.h"
#include "private.h"
#include "driver/xen.h"
#include "driver/interface.h"
#include "driver/memory_cache.h"

#if ENABLE_XEN == 1
#define _GNU_SOURCE
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <xs.h>
#include <xen/hvm/save.h>

//----------------------------------------------------------------------------
// Helper functions

//----------------------------------------------------------------------------
// Xen-Specific Interface Functions (no direct mapping to driver_*)

static xen_instance_t *xen_get_instance (vmi_instance_t vmi)
{
    return ((xen_instance_t *)vmi->driver);
}

static libvmi_xenctrl_handle_t
xen_get_xchandle (vmi_instance_t vmi)
{
    return xen_get_instance(vmi)->xchandle;
}

//TODO assuming length == page size is safe for now, but isn't the most clean approach
void *xen_get_memory_pfn (vmi_instance_t vmi, addr_t pfn, int prot)
{
    void *memory = xc_map_foreign_range (xen_get_xchandle(vmi),
                                         xen_get_domainid(vmi),
                                         XC_PAGE_SIZE,
                                         prot,
                                         (unsigned long) pfn);

    if (MAP_FAILED == memory || NULL == memory) {
        dbprint("--xen_get_memory_pfn failed on pfn=0x%llx\n", pfn);
        return NULL;
    }

#ifdef VMI_DEBUG
    // copy memory to local address space - handy for examination
    uint8_t buf[XC_PAGE_SIZE];
    memcpy (buf, memory, XC_PAGE_SIZE);
#endif // VMI_DEBUG

    return memory;
}

void *xen_get_memory (vmi_instance_t vmi, addr_t paddr, uint32_t length)
{
    addr_t pfn = paddr >> vmi->page_shift;
//TODO assuming length == page size is safe for now, but isn't the most clean approach
    return xen_get_memory_pfn(vmi, pfn, PROT_READ);
}

void xen_release_memory (void *memory, size_t length)
{
    munmap(memory, length);
}

status_t xen_put_memory (vmi_instance_t vmi, addr_t paddr, uint32_t count, void *buf)
{
    unsigned char *memory = NULL;
    addr_t phys_address = 0;
    addr_t pfn = 0;
    addr_t offset = 0;
    size_t buf_offset = 0;

    while (count > 0){
        size_t write_len = 0;

        /* access the memory */
        phys_address = paddr + buf_offset;
        pfn = phys_address >> vmi->page_shift;
        offset = (vmi->page_size - 1) & phys_address;
        memory = xen_get_memory_pfn(vmi, pfn, PROT_WRITE);
        if (NULL == memory){
            return VMI_FAILURE;
        }

        /* determine how much we can write */
        if ((offset + count) > vmi->page_size){
            write_len = vmi->page_size - offset;
        }
        else{
            write_len = count;
        }

        /* do the write */
        memcpy(memory + offset, ((char *) buf) + buf_offset, write_len);

        /* set variables for next loop */
        count -= write_len;
        buf_offset += write_len;
        xen_release_memory(memory, vmi->page_size);
    }

    return VMI_SUCCESS;
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

// formerly vmi_get_domain_id
unsigned long xen_get_domainid_from_name (vmi_instance_t vmi, char *name)
{
    char **domains = NULL;
    int size = 0;
    int i = 0;
    xs_transaction_t xth = XBT_NULL;
    unsigned long domainid = 0;
    char tmp[100];

    struct xs_handle *xsh = OPEN_XS_DAEMON();
    if (!xsh) goto _bail;

    domains = xs_directory(xsh, xth, "/local/domain", &size);
    for (i = 0; i < size; ++i){
        /* read in name */
        char *idStr = domains[i];
        snprintf(tmp, sizeof(tmp), "/local/domain/%s/name", idStr);
        char *nameCandidate = xs_read(xsh, xth, tmp, NULL);

        // if name matches, then return number
        if (nameCandidate != NULL && strncmp(name, nameCandidate, 100) == 0){
            int idNum = atoi(idStr);
            domainid = (unsigned long) idNum;
            free(nameCandidate);
            break;
        }

        /* free memory as we go */
        if (nameCandidate) free(nameCandidate);
    }

_bail:
    if (domains) free(domains);
    if (xsh)     CLOSE_XS_DAEMON(xsh);
    return domainid;
}

unsigned long xen_get_domainid (vmi_instance_t vmi)
{
    return xen_get_instance(vmi)->domainid;
}

void xen_set_domainid (vmi_instance_t vmi, unsigned long domainid)
{
    xen_get_instance(vmi)->domainid = domainid;
}

static status_t
xen_discover_guest_addr_width (vmi_instance_t vmi)
{
    int rc;
    status_t ret = VMI_FAILURE;
    
    xen_get_instance(vmi)->addr_width = 0;
    
    if (xen_get_instance(vmi)->hvm) {        // HVM
        struct hvm_hw_cpu hw_ctxt = {0};

        rc = xc_domain_hvm_getcontext_partial (xen_get_xchandle(vmi),
                                               xen_get_domainid(vmi),
                                               HVM_SAVE_CODE(CPU),
                                               0, //vcpu,
                                               &hw_ctxt,
                                               sizeof (hw_ctxt));
        if (rc != 0) {
            errprint("Failed to get context information (HVM domain).\n");
            ret = VMI_FAILURE;
            goto _bail;
        }
        xen_get_instance(vmi)->addr_width =
            (vmi_get_bit (hw_ctxt.msr_efer, 8) == 0 ? 4 : 8);
    } else {        // PV
        xen_domctl_t domctl = {0};
        domctl.domain = xen_get_domainid(vmi);

        // TODO: test this on a 32-bit PV guest
        // Note: it appears that this DOMCTL does not wok on an HVM
        domctl.cmd    = XEN_DOMCTL_get_address_size;

        // This DOMCTL always returns 0 (Xen 4.1.2)
        //domctl.cmd    = XEN_DOMCTL_get_machine_address_size;

        rc = xc_domctl (xen_get_instance(vmi)->xchandle, &domctl);
        if (rc) {
            errprint ("Failed to get domain address width (#1), value retrieved %d\n",
                      domctl.u.address_size.size);
            goto _bail;
        } // if

        // translate width to bytes from bits
        xen_get_instance(vmi)->addr_width = domctl.u.address_size.size / 8;

        if (8 != xen_get_instance(vmi)->addr_width &&
            4 != xen_get_instance(vmi)->addr_width   ) {
            errprint ("Failed to get domain address width (#2), value retrieved %d\n",
                      domctl.u.address_size.size);
            goto _bail;
        }

        dbprint ("**guest address width is %d bits\n", xen_get_instance(vmi)->addr_width * 8);
    } // if-else

    ret = VMI_SUCCESS;

_bail:
    return ret;
}

status_t xen_init (vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;
    libvmi_xenctrl_handle_t xchandle = XENCTRL_HANDLE_INVALID;
    int rc = 0; // return codes from xc_* calls

    /* open handle to the libxc interface */
    xchandle = xc_interface_open(
#ifdef XENCTRL_HAS_XC_INTERFACE // Xen >= 4.1
        NULL, NULL, 0
#endif
        );

    if (XENCTRL_HANDLE_INVALID == xchandle) {
        errprint("Failed to open libxc interface.\n");
        goto _bail;
    }
    xen_get_instance(vmi)->xchandle = xchandle;

    /* initialize other xen-specific values */

    /* setup the info struct */
    rc = xc_domain_getinfo(xchandle, xen_get_domainid(vmi), 1, &(xen_get_instance(vmi)->info));
    if (rc != 1) {
        errprint("Failed to get domain info for Xen.\n");
        goto _bail;
    }

    xen_get_instance(vmi)->xshandle = OPEN_XS_DAEMON();
    if (!xen_get_instance(vmi)->xshandle) {
        errprint("xs_domain_open failed\n");
        goto _bail;
    }

    /* determine if target is hvm or pv */
    vmi->hvm = xen_get_instance(vmi)->hvm = xen_get_instance(vmi)->info.hvm;
#ifdef VMI_DEBUG
    if (xen_get_instance(vmi)->hvm){
        dbprint("**set hvm to true (HVM).\n");
    }
    else{
        dbprint("**set hvm to false (PV).\n");
    }
#endif /* VMI_DEBUG */

    memory_cache_init(vmi, xen_get_memory, xen_release_memory, 0);

    // Determine the guest address width
    ret = xen_discover_guest_addr_width (vmi);

_bail:
    return ret;
}

void xen_destroy (vmi_instance_t vmi)
{
    xen_get_instance(vmi)->domainid = 0;
    xc_interface_close(xen_get_xchandle(vmi));
    CLOSE_XS_DAEMON(xen_get_instance(vmi)->xshandle);
}

status_t xen_get_domainname (vmi_instance_t vmi, char **name)
{
    status_t ret = VMI_FAILURE;
    xs_transaction_t xth = XBT_NULL;
    char tmp[100] = {0};

    snprintf(tmp, sizeof(tmp), "/local/domain/%d/name", xen_get_domainid(vmi));

    *name = xs_read(xen_get_instance(vmi)->xshandle, xth, tmp, NULL);
    if (NULL == name){
        errprint("Domain ID %d is not running.\n", xen_get_domainid(vmi));
        goto _bail;
    }
    ret = VMI_SUCCESS;

_bail:
    return ret;
}

void xen_set_domainname (vmi_instance_t vmi, char *name)
{
    xen_get_instance(vmi)->name = strndup(name, 500);
}

status_t xen_get_memsize (vmi_instance_t vmi, unsigned long *size)
{
    // note: may also available through PAGE_SIZE * xen_get_instance(vmi)->info.nr_pages
    // or xen_get_instance(vmi)->info.max_memkb
    status_t ret = VMI_FAILURE;
    char *tmp = NULL;
    xs_transaction_t xth = XBT_NULL;
    char path[100] = {0};

    /* get the memory size from the xenstore */
    snprintf(path, sizeof(path), "/local/domain/%d/memory/target", xen_get_domainid(vmi));
    tmp = xs_read(xen_get_instance(vmi)->xshandle, xth, path, NULL);

    if(!tmp){
        errprint("failed to retrieve memory size for Xen domain from xenstore.\n");
        goto _bail;
    }

    *size = strtol(tmp, NULL, 10) * 1024;

    if(errno){
        errprint("failed to get memory size for Xen domain.\n");
        goto _bail;
    }
    ret = VMI_SUCCESS;

_bail:
    if (tmp) free(tmp);
    
    return ret;
}

static status_t
xen_get_vcpureg_hvm (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    status_t ret = VMI_SUCCESS;
    struct hvm_hw_cpu hw_ctxt = {0};

    if (xc_domain_hvm_getcontext_partial (xen_get_xchandle(vmi),
                                          xen_get_domainid(vmi),
                                          HVM_SAVE_CODE(CPU),
                                          vcpu,
                                          &hw_ctxt,
                                          sizeof hw_ctxt) != 0) {
        errprint("Failed to get context information (HVM domain).\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    switch (reg){
        case RAX:
            *value = (reg_t) hw_ctxt.rax;
            break;
        case RBX:
            *value = (reg_t) hw_ctxt.rbx;
            break;
        case RCX:
            *value = (reg_t) hw_ctxt.rcx;
            break;
        case RDX:
            *value = (reg_t) hw_ctxt.rdx;
            break;
        case RBP:
            *value = (reg_t) hw_ctxt.rbp;
            break;
        case RSI:
            *value = (reg_t) hw_ctxt.rsi;
            break;
        case RDI:
            *value = (reg_t) hw_ctxt.rdi;
            break;
        case RSP:
            *value = (reg_t) hw_ctxt.rsp;
            break;
        case R8:
            *value = (reg_t) hw_ctxt.r8;
            break;
        case R9:
            *value = (reg_t) hw_ctxt.r9;
            break;
        case R10:
            *value = (reg_t) hw_ctxt.r10;
            break;
        case R11:
            *value = (reg_t) hw_ctxt.r11;
            break;
        case R12:
            *value = (reg_t) hw_ctxt.r12;
            break;
        case R13:
            *value = (reg_t) hw_ctxt.r13;
            break;
        case R14:
            *value = (reg_t) hw_ctxt.r14;
            break;
        case R15:
            *value = (reg_t) hw_ctxt.r15;
            break;
        case RIP:
            *value = (reg_t) hw_ctxt.rip;
            break;
        case RFLAGS:
            *value = (reg_t) hw_ctxt.rflags;
            break;

        case CR0:
            *value = (reg_t) hw_ctxt.cr0;
            break;
        case CR2:
            *value = (reg_t) hw_ctxt.cr2;
            break;
        case CR3:
            *value = (reg_t) hw_ctxt.cr3;
            break;
        case CR4:
            *value = (reg_t) hw_ctxt.cr4;
            break;

        case DR0:
            *value = (reg_t) hw_ctxt.dr0;
            break;
        case DR1:
            *value = (reg_t) hw_ctxt.dr1;
            break;
        case DR2:
            *value = (reg_t) hw_ctxt.dr2;
            break;
        case DR3:
            *value = (reg_t) hw_ctxt.dr3;
            break;
        case DR6:
            *value = (reg_t) hw_ctxt.dr6;
            break;
        case DR7:
            *value = (reg_t) hw_ctxt.dr7;
            break;

        case CS_SEL:
            *value = (reg_t) hw_ctxt.cs_sel;
            break;
        case DS_SEL:
            *value = (reg_t) hw_ctxt.ds_sel;
            break;
        case ES_SEL:
            *value = (reg_t) hw_ctxt.es_sel;
            break;
        case FS_SEL:
            *value = (reg_t) hw_ctxt.fs_sel;
            break;
        case GS_SEL:
            *value = (reg_t) hw_ctxt.gs_sel;
            break;
        case SS_SEL:
            *value = (reg_t) hw_ctxt.ss_sel;
            break;
        case TR_SEL:
            *value = (reg_t) hw_ctxt.tr_sel;
            break;
        case LDTR_SEL:
            *value = (reg_t) hw_ctxt.ldtr_sel;
            break;

        case CS_LIMIT:
            *value = (reg_t) hw_ctxt.cs_limit;
            break;
        case DS_LIMIT:
            *value = (reg_t) hw_ctxt.ds_limit;
            break;
        case ES_LIMIT:
            *value = (reg_t) hw_ctxt.es_limit;
            break;
        case FS_LIMIT:
            *value = (reg_t) hw_ctxt.fs_limit;
            break;
        case GS_LIMIT:
            *value = (reg_t) hw_ctxt.gs_limit;
            break;
        case SS_LIMIT:
            *value = (reg_t) hw_ctxt.ss_limit;
            break;
        case TR_LIMIT:
            *value = (reg_t) hw_ctxt.tr_limit;
            break;
        case LDTR_LIMIT:
            *value = (reg_t) hw_ctxt.ldtr_limit;
            break;
        case IDTR_LIMIT:
            *value = (reg_t) hw_ctxt.idtr_limit;
            break;
        case GDTR_LIMIT:
            *value = (reg_t) hw_ctxt.gdtr_limit;
            break;

        case CS_BASE:
            *value = (reg_t) hw_ctxt.cs_base;
            break;
        case DS_BASE:
            *value = (reg_t) hw_ctxt.ds_base;
            break;
        case ES_BASE:
            *value = (reg_t) hw_ctxt.es_base;
            break;
        case FS_BASE:
            *value = (reg_t) hw_ctxt.fs_base;
            break;
        case GS_BASE:
            *value = (reg_t) hw_ctxt.gs_base;
            break;
        case SS_BASE:
            *value = (reg_t) hw_ctxt.ss_base;
            break;
        case TR_BASE:
            *value = (reg_t) hw_ctxt.tr_base;
            break;
        case LDTR_BASE:
            *value = (reg_t) hw_ctxt.ldtr_base;
            break;
        case IDTR_BASE:
            *value = (reg_t) hw_ctxt.idtr_base;
            break;
        case GDTR_BASE:
            *value = (reg_t) hw_ctxt.gdtr_base;
            break;

        case CS_ARBYTES:
            *value = (reg_t) hw_ctxt.cs_arbytes;
            break;
        case DS_ARBYTES:
            *value = (reg_t) hw_ctxt.ds_arbytes;
            break;
        case ES_ARBYTES:
            *value = (reg_t) hw_ctxt.es_arbytes;
            break;
        case FS_ARBYTES:
            *value = (reg_t) hw_ctxt.fs_arbytes;
            break;
        case GS_ARBYTES:
            *value = (reg_t) hw_ctxt.gs_arbytes;
            break;
        case SS_ARBYTES:
            *value = (reg_t) hw_ctxt.ss_arbytes;
            break;
        case TR_ARBYTES:
            *value = (reg_t) hw_ctxt.tr_arbytes;
            break;
        case LDTR_ARBYTES:
            *value = (reg_t) hw_ctxt.ldtr_arbytes;
            break;

        case SYSENTER_CS:
            *value = (reg_t) hw_ctxt.sysenter_cs;
            break;
        case SYSENTER_ESP:
            *value = (reg_t) hw_ctxt.sysenter_esp;
            break;
        case SYSENTER_EIP:
            *value = (reg_t) hw_ctxt.sysenter_eip;
            break;
        case SHADOW_GS:
            *value = (reg_t) hw_ctxt.shadow_gs;
            break;

        case MSR_FLAGS:
            *value = (reg_t) hw_ctxt.msr_flags;
            break;
        case MSR_LSTAR:
            *value = (reg_t) hw_ctxt.msr_lstar;
            break;
        case MSR_CSTAR:
            *value = (reg_t) hw_ctxt.msr_cstar;
            break;
        case MSR_SYSCALL_MASK:
            *value = (reg_t) hw_ctxt.msr_syscall_mask;
            break;
        case MSR_EFER:
            *value = (reg_t) hw_ctxt.msr_efer;
            break;

#ifdef DECLARE_HVM_SAVE_TYPE_COMPAT
/* Handle churn in struct hvm_hw_cpu (from xen/hvm/save.h) 
 * that would prevent otherwise-compatible Xen 4.0 branches
 * from building.
 *
 * Checking this is less than ideal, but seemingly
 * the cleanest means of accomplishing the necessary check.
 *
 * see http://xenbits.xen.org/hg/xen-4.0-testing.hg/rev/57721c697c46
 */
        case MSR_TSC_AUX:
            *value = (reg_t) hw_ctxt.msr_tsc_aux;
            break;
#endif  

        case TSC:
            *value = (reg_t) hw_ctxt.tsc;
            break;
        default:
            ret = VMI_FAILURE;
            break;
    }

_bail:
    return ret;
}

static status_t
xen_get_vcpureg_pv64 (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    status_t ret = VMI_SUCCESS;
    vcpu_guest_context_any_t ctx = {0};
    xen_domctl_t domctl = {0};

    if (xc_vcpu_getcontext (xen_get_xchandle(vmi), 
                            xen_get_domainid(vmi),
                            vcpu, &ctx)          ) {
        errprint("Failed to get context information (PV domain).\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    switch (reg) {
        case RAX:
            *value = (reg_t) ctx.x64.user_regs.rax;
            break;
        case RBX:
            *value = (reg_t) ctx.x64.user_regs.rbx;
            break;
        case RCX:
            *value = (reg_t) ctx.x64.user_regs.rcx;
            break;
        case RDX:
            *value = (reg_t) ctx.x64.user_regs.rdx;
            break;
        case RBP:
            *value = (reg_t) ctx.x64.user_regs.rbp;
            break;
        case RSI:
            *value = (reg_t) ctx.x64.user_regs.rsi;
            break;
        case RDI:
            *value = (reg_t) ctx.x64.user_regs.rdi;
            break;
        case RSP:
            *value = (reg_t) ctx.x64.user_regs.rsp;
            break;
        case R8:
            *value = (reg_t) ctx.x64.user_regs.r8;
            break;
        case R9:
            *value = (reg_t) ctx.x64.user_regs.r9;
            break;
        case R10:
            *value = (reg_t) ctx.x64.user_regs.r10;
            break;
        case R11:
            *value = (reg_t) ctx.x64.user_regs.r11;
            break;
        case R12:
            *value = (reg_t) ctx.x64.user_regs.r12;
            break;
        case R13:
            *value = (reg_t) ctx.x64.user_regs.r13;
            break;
        case R14:
            *value = (reg_t) ctx.x64.user_regs.r14;
            break;
        case R15:
            *value = (reg_t) ctx.x64.user_regs.r15;
            break;

        case RIP:
            *value = (reg_t) ctx.x64.user_regs.rip;
            break;
        case RFLAGS:
            *value = (reg_t) ctx.x64.user_regs.rflags;
            break;

        case CR0:
            *value = (reg_t) ctx.x64.ctrlreg[0];
            break;
        case CR2:
            *value = (reg_t) ctx.x64.ctrlreg[2];
            break;
        case CR3:
            *value = (reg_t) ctx.x64.ctrlreg[3];
            *value = (reg_t) xen_cr3_to_pfn_x86_64 (*value) << XC_PAGE_SHIFT;
            break;
        case CR4:
            *value = (reg_t) ctx.x64.ctrlreg[4];
            break;

        case DR0:
            *value = (reg_t) ctx.x64.debugreg[0];
            break;
        case DR1:
            *value = (reg_t) ctx.x64.debugreg[1];
            break;
        case DR2:
            *value = (reg_t) ctx.x64.debugreg[2];
            break;
        case DR3:
            *value = (reg_t) ctx.x64.debugreg[3];
            break;
        case DR6:
            *value = (reg_t) ctx.x64.debugreg[6];
            break;
        case DR7:
            *value = (reg_t) ctx.x64.debugreg[7];
            break;
        case FS_BASE:
            *value = (reg_t) ctx.x64.fs_base;
            break;
        case GS_BASE: // TODO: distinguish between kernel & user
            *value = (reg_t) ctx.x64.gs_base_kernel;
            break;
        case LDTR_BASE:
            *value = (reg_t) ctx.x64.ldt_base;
            break;
        default:
            ret = VMI_FAILURE;
            break;
    }

_bail:
    return ret;
}


static status_t
xen_get_vcpureg_pv32 (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    status_t ret = VMI_SUCCESS;
    vcpu_guest_context_any_t ctx = {0};
    xen_domctl_t domctl = {0};

    if (xc_vcpu_getcontext (xen_get_xchandle(vmi), 
                            xen_get_domainid(vmi),
                            vcpu, &ctx)          ) {
        errprint("Failed to get context information (PV domain).\n");
        ret = VMI_FAILURE;
        goto _bail;
    }

    switch (reg) {
        case RAX:
            *value = (reg_t) ctx.x32.user_regs.eax;
            break;
        case RBX:
            *value = (reg_t) ctx.x32.user_regs.ebx;
            break;
        case RCX:
            *value = (reg_t) ctx.x32.user_regs.ecx;
            break;
        case RDX:
            *value = (reg_t) ctx.x32.user_regs.edx;
            break;
        case RBP:
            *value = (reg_t) ctx.x32.user_regs.ebp;
            break;
        case RSI:
            *value = (reg_t) ctx.x32.user_regs.esi;
            break;
        case RDI:
            *value = (reg_t) ctx.x32.user_regs.edi;
            break;
        case RSP:
            *value = (reg_t) ctx.x32.user_regs.esp;
            break;

        case RIP:
            *value = (reg_t) ctx.x32.user_regs.eip;
            break;
        case RFLAGS:
            *value = (reg_t) ctx.x32.user_regs.eflags;
            break;

        case CR0:
            *value = (reg_t) ctx.x32.ctrlreg[0];
            break;
        case CR2:
            *value = (reg_t) ctx.x32.ctrlreg[2];
            break;
        case CR3:
            *value = (reg_t) ctx.x32.ctrlreg[3];
            *value = (reg_t) xen_cr3_to_pfn_x86_32 (*value) << XC_PAGE_SHIFT;
            break;
        case CR4:
            *value = (reg_t) ctx.x32.ctrlreg[4];
            break;

        case DR0:
            *value = (reg_t) ctx.x32.debugreg[0];
            break;
        case DR1:
            *value = (reg_t) ctx.x32.debugreg[1];
            break;
        case DR2:
            *value = (reg_t) ctx.x32.debugreg[2];
            break;
        case DR3:
            *value = (reg_t) ctx.x32.debugreg[3];
            break;
        case DR6:
            *value = (reg_t) ctx.x32.debugreg[6];
            break;
        case DR7:
            *value = (reg_t) ctx.x32.debugreg[7];
            break;
        case LDTR_BASE:
            *value = (reg_t) ctx.x32.ldt_base;
            break;
        default:
            ret = VMI_FAILURE;
            break;
    }

_bail:
    return ret;
}

status_t xen_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    if (xen_get_instance(vmi)->hvm) {
        return xen_get_vcpureg_hvm (vmi, value, reg, vcpu);
    } else {
        if (8 == xen_get_instance(vmi)->addr_width) {
            return xen_get_vcpureg_pv64 (vmi, value, reg, vcpu);
        } else {
            return xen_get_vcpureg_pv32 (vmi, value, reg, vcpu);
        } // if-else
    } // if-else
}

status_t xen_get_address_width (vmi_instance_t vmi, uint8_t * width)
{
    *width = xen_get_instance(vmi)->addr_width;
    return VMI_SUCCESS;
}

void *xen_read_page (vmi_instance_t vmi, addr_t page)
{
    addr_t paddr = page << vmi->page_shift;
    return memory_cache_insert(vmi, paddr);
}

status_t xen_write (vmi_instance_t vmi, addr_t paddr, void *buf, uint32_t length)
{
    return xen_put_memory(vmi, paddr, length, buf);
}

int xen_is_pv (vmi_instance_t vmi)
{
    return !xen_get_instance(vmi)->hvm;
}

status_t xen_test (unsigned long id, char *name)
{
    id = xen_get_domainid_from_name(NULL, name);
    if (!id){
        return VMI_FAILURE;
    }
    else{
        return VMI_SUCCESS;
    }
}

status_t xen_pause_vm (vmi_instance_t vmi)
{
    if (-1 == xc_domain_pause(xen_get_xchandle(vmi), xen_get_domainid(vmi))){
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

status_t xen_resume_vm (vmi_instance_t vmi)
{
    if (-1 == xc_domain_unpause(xen_get_xchandle(vmi), xen_get_domainid(vmi))){
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////
#else

status_t xen_init (vmi_instance_t vmi) { return VMI_FAILURE; }
void xen_destroy (vmi_instance_t vmi) { return; }
unsigned long xen_get_domainid_from_name (vmi_instance_t vmi, char *name) { return 0; }
unsigned long xen_get_domainid (vmi_instance_t vmi) { return 0; }
void xen_set_domainid (vmi_instance_t vmi, unsigned long domainid) { return; }
status_t xen_get_domainname (vmi_instance_t vmi, char **name) { return VMI_FAILURE; }
void xen_set_domainname (vmi_instance_t vmi, char *name) { return; }
status_t xen_get_memsize (vmi_instance_t vmi, unsigned long *size) { return VMI_FAILURE; }
status_t xen_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu) { return VMI_FAILURE; }
status_t xen_get_address_width (vmi_instance_t vmi, uint8_t * width) {return VMI_FAILURE;}
void *xen_read_page (vmi_instance_t vmi, unsigned long page) { return NULL; }
status_t xen_write (vmi_instance_t vmi, addr_t paddr, void *buf, uint32_t length) { return VMI_FAILURE; }
int xen_is_pv (vmi_instance_t vmi) { return 0; }
status_t xen_test (unsigned long id, char *name) { return VMI_FAILURE; }
status_t xen_pause_vm (vmi_instance_t vmi) { return VMI_FAILURE; }
status_t xen_resume_vm (vmi_instance_t vmi) { return VMI_FAILURE; }

#endif /* ENABLE_XEN */

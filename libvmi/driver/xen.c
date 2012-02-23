/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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

//#define fpp 1024		/* number of xen_pfn_t that fits on one frame */

//----------------------------------------------------------------------------
// Helper functions

//----------------------------------------------------------------------------
// Xen-Specific Interface Functions (no direct mapping to driver_*)

static xen_instance_t *xen_get_instance (vmi_instance_t vmi)
{
    return ((xen_instance_t *)vmi->driver);
}

static
#ifdef XENCTRL_HAS_XC_INTERFACE // Xen >= 4.1
xc_interface *
#else
int
#endif
xen_get_xchandle (vmi_instance_t vmi)
{
    return xen_get_instance(vmi)->xchandle;
}

//TODO assuming length == page size is safe for now, but isn't the most clean approach
void *xen_get_memory_mfn (vmi_instance_t vmi, addr_t mfn, int prot)
{
    void *memory = xc_map_foreign_range (xen_get_xchandle(vmi),
                                         xen_get_domainid(vmi),
                                         XC_PAGE_SIZE,
                                         prot,
                                         mfn);

    if (MAP_FAILED == memory || NULL == memory) {
        dbprint("--xen_get_memory_mfn failed on mfn=0x%.16llx\n", mfn);
        return NULL;
    }
    else {
        return memory;
    }
}

void *xen_get_memory (vmi_instance_t vmi, addr_t maddr, uint32_t length)
{
    addr_t mfn = maddr >> vmi->page_shift;
//TODO assuming length == page size is safe for now, but isn't the most clean approach
    return xen_get_memory_mfn(vmi, mfn, PROT_READ);
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
    addr_t mfn = 0;
    addr_t offset = 0;
    size_t buf_offset = 0;

    while (count > 0){
        size_t write_len = 0;

        /* access the memory */
        phys_address = paddr + buf_offset;
        pfn = phys_address >> vmi->page_shift;
        mfn = xen_pfn_to_mfn(vmi, pfn);
        offset = (vmi->page_size - 1) & phys_address;
        memory = xen_get_memory_mfn(vmi, mfn, PROT_WRITE);
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
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    unsigned long domainid = 0;

    xsh = xs_domain_open();
    if (XBT_NULL == xsh) { // fail
        goto error_exit;
    } // if

    domains = xs_directory(xsh, xth, "/local/domain", &size);
    for (i = 0; i < size; ++i){
        /* read in name */
        char *tmp = safe_malloc(100);
        char *idStr = domains[i];
        snprintf(tmp, 100, "/local/domain/%s/name", idStr);
        char *nameCandidate = xs_read(xsh, xth, tmp, NULL);

        // if name matches, then return number
        if (strncmp(name, nameCandidate, 100) == 0){
            int idNum = atoi(idStr);
            domainid = (unsigned long) idNum;
            free(tmp);
            break;
        }

        /* free memory as we go */
        free(tmp);
        if (nameCandidate) free(nameCandidate);
    }

error_exit:
    if (domains) free(domains);
    if (NULL != xsh){
        xs_daemon_close(xsh);
    }
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

status_t xen_init (vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;
    xen_domctl_t domctl = {0};

    /* open handle to the libxc interface */
#ifdef XENCTRL_HAS_XC_INTERFACE // Xen >= 4.1
    xc_interface *xchandle = NULL;
    if ((xchandle = xc_interface_open(NULL, NULL, 0)) == NULL){
#else
    int xchandle = -1;
    if ((xchandle = xc_interface_open()) == -1){
#endif
        errprint("Failed to open libxc interface.\n");
        goto error_exit;
    }
    xen_get_instance(vmi)->xchandle = xchandle;

    /* initialize other xen-specific values */
    xen_get_instance(vmi)->live_pfn_to_mfn_table = NULL;
    xen_get_instance(vmi)->nr_pfns = 0;

    domctl.domain = xen_get_instance(vmi)->domainid;
    domctl.cmd    = XEN_DOMCTL_get_address_size;

    if (xc_domctl (xen_get_instance(vmi)->xchandle, &domctl)) {
        return VMI_FAILURE;
    }
    xen_get_instance(vmi)->addr_width = domctl.u.address_size.size / 8;

    xen_get_instance(vmi)->p2m_size = xc_domain_maximum_gpfn (xen_get_instance(vmi)->xchandle,
                                                              xen_get_domainid(vmi)) + 1;

    /* setup the info struct */
    if (xc_domain_getinfo(xchandle, xen_get_domainid(vmi), 1, &(xen_get_instance(vmi)->info)) != 1){
        errprint("Failed to get domain info for Xen.\n");
        goto error_exit;
    }

    /* determine if target is hvm or pv */
    xen_get_instance(vmi)->hvm = xen_get_instance(vmi)->info.hvm;
#ifdef VMI_DEBUG
    if (xen_get_instance(vmi)->hvm){
        dbprint("**set hvm to true (HVM).\n");
    }
    else{
        dbprint("**set hvm to false (PV).\n");
    }
#endif /* VMI_DEBUG */

    memory_cache_init(vmi, xen_get_memory, xen_release_memory, 0);
    ret = VMI_SUCCESS;

error_exit:
    return ret;
}

void xen_destroy (vmi_instance_t vmi)
{
    if (xen_get_instance(vmi)->live_pfn_to_mfn_table){
        xen_release_memory(
            xen_get_instance(vmi)->live_pfn_to_mfn_table,
            xen_get_instance(vmi)->nr_pfns * 4
        );
    }

    xen_get_instance(vmi)->domainid = 0;
    xc_interface_close(xen_get_xchandle(vmi));
}

status_t xen_get_domainname (vmi_instance_t vmi, char **name)
{
    // note: name also available at location xen_get_instance(vmi)->name
    status_t ret = VMI_FAILURE;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *tmp = safe_malloc(100);

    memset(tmp, 0, 100);
    snprintf(tmp, 100, "/local/domain/%d/name", xen_get_domainid(vmi));
    xsh = xs_domain_open();
    *name = xs_read(xsh, xth, tmp, NULL);
    if (NULL == name){
        errprint("Domain ID %d is not running.\n", xen_get_domainid(vmi));
        goto error_exit;
    }
    ret = VMI_SUCCESS;

error_exit:
    return ret;
}

void xen_set_domainname (vmi_instance_t vmi, char *name)
{
    xen_get_instance(vmi)->name = strndup(name, 500);
}

status_t xen_get_memsize (vmi_instance_t vmi, unsigned long *size)
{
    // note: may also available through PAGE_SIZE * xen_get_instance(vmi)->nr_pages
    // or xen_get_instance(vmi)->max_memkb
    status_t ret = VMI_FAILURE;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;

    char *tmp = safe_malloc(100);
    memset(tmp, 0, 100);

    /* get the memory size from the xenstore */
    snprintf(tmp, 100, "/local/domain/%d/memory/target", xen_get_domainid(vmi));
    xsh = xs_domain_open();
    *size = strtol(xs_read(xsh, xth, tmp, NULL), NULL, 10) * 1024;
    if (!size){
        errprint("failed to get memory size for Xen domain.\n");
        goto error_exit;
    }
    ret = VMI_SUCCESS;

error_exit:
    if (NULL != xsh){
        xs_daemon_close(xsh);
    }
    free(tmp);
    return ret;
}

static status_t
xen_get_vcpureg_hvm (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    status_t ret = VMI_SUCCESS;
    struct hvm_hw_cpu hw_ctxt;
    memset(&hw_ctxt, 0, sizeof(struct hvm_hw_cpu));

    if (xc_domain_hvm_getcontext_partial(
            xen_get_xchandle(vmi),
            xen_get_domainid(vmi),
            HVM_SAVE_CODE(CPU),
            vcpu,
            &hw_ctxt,
            sizeof hw_ctxt) != 0){
        errprint("Failed to get context information (HVM domain).\n");
        ret = VMI_FAILURE;
        goto error_exit;
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
            *value = (reg_t) hw_ctxt.rbx;
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
        case MSR_TSC_AUX:
            *value = (reg_t) hw_ctxt.msr_tsc_aux;
            break;

        case TSC:
            *value = (reg_t) hw_ctxt.tsc;
            break;
        default:
            ret = VMI_FAILURE;
            break;
    }

error_exit:
    return ret;
}

static status_t
xen_get_vcpureg_pv (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    // TODO: dupe this function for 32 bit context
    status_t ret = VMI_SUCCESS;
    vcpu_guest_context_any_t ctx = {0};
    xen_domctl_t domctl = {0};

    // broken under Xen 4.1.2: getting bad values for CR3
    if (xc_vcpu_getcontext (xen_get_xchandle(vmi), 
                            xen_get_domainid(vmi),
                            vcpu, &ctx)          ) {
        errprint("Failed to get context information (PV domain).\n");
        ret = VMI_FAILURE;
        goto error_exit;
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
            *value = (reg_t) ctx.x64.user_regs.rbx;
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
            domctl.domain = xen_get_instance(vmi)->domainid;
            domctl.cmd    = XEN_DOMCTL_get_address_size;
            if (xc_domctl (xen_get_instance(vmi)->xchandle, &domctl)) {
                errprint ("Failed to discover domain address width\n");
                return VMI_FAILURE;
            }
            // assumption: size in (32,64)
            if (64 == domctl.u.address_size.size) {
                *value = (reg_t) ctx.x64.ctrlreg[3];
                *value = (reg_t) xen_cr3_to_pfn_x86_64 (*value) << XC_PAGE_SHIFT;
            } else {
                *value = (reg_t) ctx.x32.ctrlreg[3];
                *value = (reg_t) xen_cr3_to_pfn_x86_32 (*value) << XC_PAGE_SHIFT;
            } // if

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
/*
These values are not readily available from ctx.
        case CS_SEL:
            *value = (reg_t) ctx.cs_sel;
            break;
        case DS_SEL:
            *value = (reg_t) ctx.ds_sel;
            break;
        case ES_SEL:
            *value = (reg_t) ctx.es_sel;
            break;
        case FS_SEL:
            *value = (reg_t) ctx.fs_sel;
            break;
        case GS_SEL:
            *value = (reg_t) ctx.gs_sel;
            break;
        case SS_SEL:
            *value = (reg_t) ctx.ss_sel;
            break;
        case TR_SEL:
            *value = (reg_t) ctx.tr_sel;
            break;
        case LDTR_SEL:
            *value = (reg_t) ctx.ldtr_sel;
            break;

        case CS_LIMIT:
            *value = (reg_t) ctx.cs_limit;
            break;
        case DS_LIMIT:
            *value = (reg_t) ctx.ds_limit;
            break;
        case ES_LIMIT:
            *value = (reg_t) ctx.es_limit;
            break;
        case FS_LIMIT:
            *value = (reg_t) ctx.fs_limit;
            break;
        case GS_LIMIT:
            *value = (reg_t) ctx.gs_limit;
            break;
        case SS_LIMIT:
            *value = (reg_t) ctx.ss_limit;
            break;
        case TR_LIMIT:
            *value = (reg_t) ctx.tr_limit;
            break;
        case LDTR_LIMIT:
            *value = (reg_t) ctx.ldtr_limit;
            break;
        case IDTR_LIMIT:
            *value = (reg_t) ctx.idtr_limit;
            break;
        case GDTR_LIMIT:
            *value = (reg_t) ctx.gdtr_limit;
            break;

        case CS_BASE:
            *value = (reg_t) ctx.cs_base;
            break;
        case DS_BASE:
            *value = (reg_t) ctx.ds_base;
            break;
        case ES_BASE:
            *value = (reg_t) ctx.es_base;
            break;
*/
        case FS_BASE:
            *value = (reg_t) ctx.x64.fs_base;
            break;
        case GS_BASE: // TODO: distinguish between kernel & user
            *value = (reg_t) ctx.x64.gs_base_kernel;
            break;
/*
        case SS_BASE:
            *value = (reg_t) ctx.ss_base;
            break;
        case TR_BASE:
            *value = (reg_t) ctx.tr_base;
            break;
*/
        case LDTR_BASE:
            *value = (reg_t) ctx.x64.ldt_base;
            break;
/*
        case IDTR_BASE:
            *value = (reg_t) ctx.idtr_base;
            break;
        case GDTR_BASE:
            *value = (reg_t) ctx.gdtr_base;
            break;

        case CS_ARBYTES:
            *value = (reg_t) ctx.cs_arbytes;
            break;
        case DS_ARBYTES:
            *value = (reg_t) ctx.ds_arbytes;
            break;
        case ES_ARBYTES:
            *value = (reg_t) ctx.es_arbytes;
            break;
        case FS_ARBYTES:
            *value = (reg_t) ctx.fs_arbytes;
            break;
        case GS_ARBYTES:
            *value = (reg_t) ctx.gs_arbytes;
            break;
        case SS_ARBYTES:
            *value = (reg_t) ctx.ss_arbytes;
            break;
        case TR_ARBYTES:
            *value = (reg_t) ctx.tr_arbytes;
            break;
        case LDTR_ARBYTES:
            *value = (reg_t) ctx.ldtr_arbytes;
            break;

        case SYSENTER_CS:
            *value = (reg_t) ctx.sysenter_cs;
            break;
        case SYSENTER_ESP:
            *value = (reg_t) ctx.sysenter_esp;
            break;
        case SYSENTER_EIP:
            *value = (reg_t) ctx.sysenter_eip;
            break;
        case SHADOW_GS:
            *value = (reg_t) ctx.shadow_gs;
            break;

        case MSR_FLAGS:
            *value = (reg_t) ctx.msr_flags;
            break;
        case MSR_LSTAR:
            *value = (reg_t) ctx.msr_lstar;
            break;
        case MSR_CSTAR:
            *value = (reg_t) ctx.msr_cstar;
            break;
        case MSR_SYSCALL_MASK:
            *value = (reg_t) ctx.msr_syscall_mask;
            break;
        case MSR_EFER:
            *value = (reg_t) ctx.msr_efer;
            break;
        case MSR_TSC_AUX:
            *value = (reg_t) ctx.msr_tsc_aux;
            break;

        case TSC:
            *value = (reg_t) ctx.x64.tsc;
            break;
*/
        default:
            ret = VMI_FAILURE;
            break;
    }

error_exit:
    return ret;
}

status_t xen_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    if (xen_get_instance(vmi)->hvm) {
        return xen_get_vcpureg_hvm (vmi, value, reg, vcpu);
    } else {
        return xen_get_vcpureg_pv  (vmi, value, reg, vcpu);
    }
}

status_t xen_get_address_width (vmi_instance_t vmi, uint8_t * width)
{
    *width = xen_get_instance(vmi)->addr_width;
    return VMI_SUCCESS;
}


addr_t xen_pfn_to_mfn (vmi_instance_t vmi, addr_t pfn)
{
    // see xc_domain_save.c:map_and_save_p2m_table for template code

    // HVM code
    if (xen_get_instance(vmi)->hvm) {
        return pfn;
    }

    // PV code

    shared_info_t *live_shinfo     = 0;
    uint32_t nr_pfns = 0;
    uint64_t fll     = 0;

    void *live_p2m_frame_list_list = 0;
    void *live_p2m_frame_list      = 0;

    xen_pfn_t *p2m_frame_list_list = 0;
    xen_pfn_t *p2m_frame_list      = 0;

    xen_pfn_t *p2m = 0;
    addr_t ret = 0; // 0 is value indicating error

    int i;

    if (xen_get_instance(vmi)->live_pfn_to_mfn_table) {
        return xen_get_instance(vmi)->live_pfn_to_mfn_table[pfn];
    } // if

    // guest width
#define GW (xen_get_instance(vmi)->addr_width)

    // based on defns in xen/tools/libxc/xg_private.h
#define FPP                (XC_PAGE_SIZE/GW)
#define P2M_FLL_ENTRIES    ((xen_get_instance(vmi)->p2m_size + (FPP * FPP)-1) / (FPP * FPP))
#define P2M_FL_ENTRIES     (((xen_get_instance(vmi)->p2m_size) + FPP-1) / FPP)
#define P2M_GUEST_FL_SIZE  (P2M_FLL_ENTRIES * GW)
#define P2M_TOOLS_FL_SIZE  (P2M_FLL_ENTRIES * MAX(sizeof(xen_pfn_t), GW))
    
    dbprint ("GW (guest width):  %d\n", GW               );
    dbprint ("XC_PAGE_SIZE:      %d\n", XC_PAGE_SIZE     );
    dbprint ("FPP:               %d\n", FPP              );
    dbprint ("P2M_FLL_ENTRIES:   %d\n", P2M_FLL_ENTRIES  );
    dbprint ("P2M_FL_ENTRIES:    %d\n", P2M_FL_ENTRIES   );
    dbprint ("P2M_GUEST_FL_SIZE: %d\n", P2M_GUEST_FL_SIZE);
    dbprint ("P2M_TOOLS_FL_SIZE: %d\n", P2M_TOOLS_FL_SIZE);

    // init live_pfn_to_mfn_table
    live_shinfo =
        xc_map_foreign_range (xen_get_instance(vmi)->xchandle,
                              xen_get_instance(vmi)->domainid,
                              XC_PAGE_SIZE,
                              PROT_READ,
                              xen_get_instance(vmi)->info.shared_info_frame);
    if (!live_shinfo) {
        errprint("Failed to init live_shinfo.\n");
        perror ("xc_map_foreign_range (0)");
        goto _done;
    }

    nr_pfns = live_shinfo->arch.max_pfn;
    fll = live_shinfo->arch.pfn_to_mfn_frame_list_list;

    live_p2m_frame_list_list =
        xc_map_foreign_range (xen_get_instance(vmi)->xchandle,
                              xen_get_instance(vmi)->domainid,
                              XC_PAGE_SIZE, PROT_READ, fll);
    if (!live_p2m_frame_list_list) {
        errprint ("Failed to acquire live_p2m_frame_list_list.\n");
        perror ("xc_map_foreign_range (1)");
        goto _done;
    }

    // get local copy
    p2m_frame_list_list = safe_malloc (XC_PAGE_SIZE);
    memcpy (p2m_frame_list_list, live_p2m_frame_list_list, XC_PAGE_SIZE);
    //munmap (live_p2m_frame_list_list, XC_PAGE_SIZE);
    //live_p2m_frame_list_list = 0;

    // Canonicalize guest's unsigned long vs ours
    if (GW > sizeof(unsigned long)) {
        for (i = 0; i < XC_PAGE_SIZE/GW; i++) {
            if (i < XC_PAGE_SIZE/GW) {
                p2m_frame_list_list[i] = ((uint64_t *)p2m_frame_list_list)[i];
            } else {
                p2m_frame_list_list[i] = 0;
            } // if-else
        }
    } else if (GW < sizeof(unsigned long)) {
        for (i = XC_PAGE_SIZE/sizeof(unsigned long) - 1; i >= 0; i--) {
            p2m_frame_list_list[i] = ((uint32_t *)p2m_frame_list_list)[i];
        }
    } // if-else

    live_p2m_frame_list =
        xc_map_foreign_pages (xen_get_instance(vmi)->xchandle,
                              xen_get_instance(vmi)->domainid,
                              PROT_READ, p2m_frame_list_list, P2M_FLL_ENTRIES);
    if (!live_p2m_frame_list) {
        errprint ("Failed to acquire live_p2m_frame_list.\n");
        perror ("xc_map_foreign_range (2)");
        goto _done;
    }

    // get local copy, note PM2_TOOLS_FL_SIZE >= P2M_GUEST_FL_SIZE
    p2m_frame_list = safe_malloc (P2M_TOOLS_FL_SIZE);
    memset (p2m_frame_list, 0, P2M_TOOLS_FL_SIZE);
    memcpy (p2m_frame_list, live_p2m_frame_list, P2M_GUEST_FL_SIZE);
    //munmap (live_p2m_frame_list, P2M_FLL_ENTRIES * XC_PAGE_SIZE);
    //live_p2m_frame_list = 0;

    // Canonicalize guest's unsigned long vs ours
    if (GW > sizeof(unsigned long)) {
        for (i = 0; i < P2M_FL_ENTRIES; i++) {
            p2m_frame_list[i] = ((uint64_t *)p2m_frame_list)[i];
        }
    } else if (GW < sizeof(unsigned long)) {
        for (i = P2M_FL_ENTRIES-1; i >= 0; i--) {
            p2m_frame_list[i] = ((uint32_t *)p2m_frame_list)[i];
        }
    } // if-else

    // fails in IOCTL in this function; errno set to EINVAL
    p2m = xc_map_foreign_pages (xen_get_instance(vmi)->xchandle,
                                xen_get_instance(vmi)->domainid,
                                PROT_READ, p2m_frame_list, P2M_FL_ENTRIES);
    if (!p2m) {
        errprint ("Failed to map p2m table.\n");
        perror ("xc_map_foreign_range (3)");
        goto _done;
    }

    // todo: canonicalize PFN to MFN table frame-number list

    xen_get_instance(vmi)->live_pfn_to_mfn_table = p2m;
    ret = p2m[pfn];

_done:
    if (live_shinfo)              xen_release_memory (live_shinfo,              XC_PAGE_SIZE);
    if (live_p2m_frame_list_list) xen_release_memory (live_p2m_frame_list_list, XC_PAGE_SIZE);
    if (live_p2m_frame_list)      xen_release_memory (live_p2m_frame_list,      XC_PAGE_SIZE);

    return ret;
} // xen_pfn_to_mfn

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
unsigned long xen_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn) { return 0; }
void *xen_read_page (vmi_instance_t vmi, unsigned long page) { return NULL; }
status_t xen_write (vmi_instance_t vmi, addr_t paddr, void *buf, uint32_t length) { return VMI_FAILURE; }
int xen_is_pv (vmi_instance_t vmi) { return 0; }
status_t xen_test (unsigned long id, char *name) { return VMI_FAILURE; }
status_t xen_pause_vm (vmi_instance_t vmi) { return VMI_FAILURE; }
status_t xen_resume_vm (vmi_instance_t vmi) { return VMI_FAILURE; }

#endif /* ENABLE_XEN */

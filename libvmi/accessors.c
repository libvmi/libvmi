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

#include "private.h"
#include "driver/driver_wrapper.h"
#include "driver/memory_cache.h"

/* NB: Necessary for windows specific API functions */
#include "os/windows/windows.h"

uint8_t vmi_get_address_width(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return 0;
#endif

    switch (vmi->page_mode) {
        case VMI_PM_AARCH64:
        case VMI_PM_IA32E:
            return 8;
        case VMI_PM_AARCH32:
        case VMI_PM_LEGACY:
        case VMI_PM_PAE:
            return 4;
        default:
            return 0;
    }
}

os_t
vmi_get_ostype(
    vmi_instance_t vmi)
{
    return
#ifdef ENABLE_SAFETY_CHECKS
        (NULL == vmi) ? VMI_OS_UNKNOWN :
#endif
        vmi->os_type;
}

bool
vmi_get_windows_build_info(
    vmi_instance_t vmi, win_build_info_t* info)
{
#ifndef ENABLE_WINDOWS
    errprint("**LibVMI wasn't compiled with Windows support!\n");
    return false;
#else
    windows_instance_t windows_instance = NULL;

#ifdef ENABLE_SAFETY_CHECKS
    if (!info || !vmi) {
        errprint("**%s:%d Error: null pointer!\n", __FUNCTION__, __LINE__);
        return false;
    }

    if (VMI_OS_WINDOWS != vmi->os_type)
        return false;

    if (!vmi->os_data) {
        return false;
    }
#endif

    windows_instance = vmi->os_data;

    if (!windows_instance->version || windows_instance->version == VMI_OS_WINDOWS_UNKNOWN) {
        addr_t kdbg = windows_instance->ntoskrnl + windows_instance->kdbg_offset;
        windows_instance->version = find_windows_version(vmi, kdbg);
    }

    info->version = windows_instance->version;
    info->buildnumber = windows_instance->build;
    info->major = windows_instance->major;
    info->minor = windows_instance->minor;

    return true;
#endif
}

win_ver_t
vmi_get_winver(
    vmi_instance_t vmi)
{
#ifndef ENABLE_WINDOWS
    errprint("**LibVMI wasn't compiled with Windows support!\n");
    return VMI_OS_WINDOWS_NONE;
#else
    windows_instance_t windows_instance = NULL;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return VMI_OS_WINDOWS_NONE;

    if (VMI_OS_WINDOWS != vmi->os_type)
        return VMI_OS_WINDOWS_NONE;

    if (!vmi->os_data) {
        return VMI_OS_WINDOWS_NONE;
    }
#endif

    windows_instance = vmi->os_data;

    if (!windows_instance->version || windows_instance->version == VMI_OS_WINDOWS_UNKNOWN) {
        addr_t kdbg = windows_instance->ntoskrnl + windows_instance->kdbg_offset;
        windows_instance->version = find_windows_version(vmi, kdbg);
    }
    return windows_instance->version;
#endif
}

uint16_t
vmi_get_win_buildnumber(
    vmi_instance_t vmi)
{
#ifndef ENABLE_WINDOWS
    errprint("**LibVMI wasn't compiled with Windows support!\n");
    return 0;
#else

#ifndef ENABLE_JSON_PROFILES
    errprint("**LibVMI wasn't compiled with JSON profiles support!\n");
    return 0;
#endif

    windows_instance_t windows_instance = NULL;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return 0;

    if (VMI_OS_WINDOWS != vmi->os_type)
        return 0;

    if (!vmi->os_data) {
        return 0;
    }

    if (!json_profile(vmi)) {
        errprint("** LibVMI wasn't initialized with JSON profile!\n");
        return 0;
    }
#endif

    windows_instance = vmi->os_data;

    return windows_instance->build;
#endif
}

const char *
vmi_get_winver_str(
    vmi_instance_t vmi)
{

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return "VMI_OS_WINDOWS_NONE";
#endif

    win_ver_t ver = vmi_get_winver(vmi);

    switch (ver) {
        case VMI_OS_WINDOWS_NONE:
            return "VMI_OS_WINDOWS_NONE";
        case VMI_OS_WINDOWS_UNKNOWN:
            return "VMI_OS_WINDOWS_UNKNOWN";
        case VMI_OS_WINDOWS_2000:
            return "VMI_OS_WINDOWS_2000";
        case VMI_OS_WINDOWS_XP:
            return "VMI_OS_WINDOWS_XP";
        case VMI_OS_WINDOWS_2003:
            return "VMI_OS_WINDOWS_2003";
        case VMI_OS_WINDOWS_VISTA:
            return "VMI_OS_WINDOWS_VISTA";
        case VMI_OS_WINDOWS_2008:
            return "VMI_OS_WINDOWS_2008";
        case VMI_OS_WINDOWS_7:
            return "VMI_OS_WINDOWS_7";
        default:
            return "<Illegal value for Windows version>";
    }   // switch
}

win_ver_t
vmi_get_winver_manual(
    vmi_instance_t vmi,
    addr_t kdbg_pa)
{
#ifdef ENABLE_WINDOWS
    return find_windows_version(vmi, kdbg_pa);
#else
    errprint("**LibVMI wasn't compiled with Windows support!\n");
    return VMI_OS_WINDOWS_NONE;
#endif
}

status_t
vmi_get_offset(
    vmi_instance_t vmi,
    const char *offset_name,
    addr_t *offset)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return VMI_FAILURE;

    if ( !vmi->os_interface || !vmi->os_interface->os_get_offset )
        return VMI_FAILURE;
#endif

    return vmi->os_interface->os_get_offset(vmi, offset_name, offset);
}

status_t
vmi_get_kernel_struct_offset(
    vmi_instance_t vmi,
    const char* symbol,
    const char* member,
    addr_t *addr)
{

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !addr)
        return 0;
#endif

    return vmi->os_interface->os_get_kernel_struct_offset(vmi, symbol, member, addr);
}

status_t vmi_get_xsave_info(
    vmi_instance_t vmi,
    unsigned long vcpu,
    xsave_area_t *xsave_info)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !xsave_info)
        return 0;
#endif

    return driver_get_xsave_info(vmi, vcpu, xsave_info);
}

uint64_t
vmi_get_memsize(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return 0;
#endif

    if ( VMI_FAILURE == driver_get_memsize(vmi, &vmi->allocated_ram_size, &vmi->max_physical_address) )
        return 0;

    return vmi->allocated_ram_size;
}

addr_t
vmi_get_max_physical_address(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return 0;
#endif

    if ( VMI_FAILURE == driver_get_memsize(vmi, &vmi->allocated_ram_size, &vmi->max_physical_address) )
        return 0;

    return vmi->max_physical_address;
}

unsigned int
vmi_get_num_vcpus(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return 0;
#endif

    return vmi->num_vcpus;
}

status_t
vmi_request_page_fault(
    vmi_instance_t vmi,
    unsigned long vcpu,
    uint64_t virtual_address,
    uint32_t error_code)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return 0;
#endif

    return driver_request_page_fault(vmi, vcpu, virtual_address, error_code);
}

status_t
vmi_get_tsc_info(
    vmi_instance_t vmi,
    uint32_t *tsc_mode,
    uint64_t *elapsed_nsec,
    uint32_t *gtsc_khz,
    uint32_t *incarnation)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return 0;
#endif
    return driver_get_tsc_info(vmi, tsc_mode, elapsed_nsec, gtsc_khz, incarnation);
}

status_t
vmi_get_vcpumtrr(
    vmi_instance_t vmi,
    mtrr_regs_t *hwMtrr,
    unsigned long vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return VMI_FAILURE;
#endif

    return driver_get_vcpumtrr(vmi, hwMtrr, vcpu);
}

status_t
vmi_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return VMI_FAILURE;
#endif

    return driver_get_vcpureg(vmi, value, reg, vcpu);
}

status_t
vmi_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !regs)
        return VMI_FAILURE;
#endif

    return driver_get_vcpuregs(vmi, regs, vcpu);
}

status_t
vmi_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return VMI_FAILURE;
#endif

    return driver_set_vcpureg(vmi, value, reg, vcpu);
}

status_t
vmi_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !regs)
        return VMI_FAILURE;
#endif

    return driver_set_vcpuregs(vmi, regs, vcpu);
}

status_t
vmi_pause_vm(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return VMI_FAILURE;
#endif

    return driver_pause_vm(vmi);
}

status_t
vmi_resume_vm(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return VMI_FAILURE;
#endif

    return driver_resume_vm(vmi);
}

char *
vmi_get_name(
    vmi_instance_t vmi)
{
    /* memory for name is allocated at the driver level */
    char *name = NULL;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return NULL;
#endif

    if (VMI_FAILURE == driver_get_name(vmi, &name)) {
        return NULL;
    } else {
        return name;
    }
}

uint64_t
vmi_get_vmid(
    vmi_instance_t vmi)
{
    uint64_t domid = VMI_INVALID_DOMID;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return 0;
#endif

    if (VMI_INVALID_DOMID == (domid = driver_get_id(vmi))) {
        char *name = vmi_get_name(vmi);
        domid = driver_get_id_from_name(vmi, name);
        free(name);
    }

    return domid;
}

/* convert a kernel symbol into an address */
status_t
vmi_translate_ksym2v(
    vmi_instance_t vmi,
    const char *symbol,
    addr_t *vaddr)
{
    status_t status = VMI_FAILURE;
    addr_t address = 0;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !symbol || !vaddr)
        return VMI_FAILURE;
#endif

    status = sym_cache_get(vmi, 0, 0, symbol, &address);

    if ( VMI_FAILURE == status ) {
        if (vmi->os_interface && vmi->os_interface->os_ksym2v) {
            addr_t _base_vaddr;
            status = vmi->os_interface->os_ksym2v(vmi, symbol, &_base_vaddr, &address);
            if ( VMI_SUCCESS == status ) {
                address = canonical_addr(address);
                sym_cache_set(vmi, 0, 0, symbol, address);
            }
        }
    }

    *vaddr = address;
    return status;
}

/* convert a symbol into an address */
status_t
vmi_translate_sym2v(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    const char *symbol,
    addr_t *vaddr)
{
    status_t status;
    addr_t rva = 0;
    addr_t address = 0;
    addr_t dtb = 0;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !ctx || !symbol || !vaddr)
        return VMI_FAILURE;
#endif

    switch (ctx->translate_mechanism) {
        case VMI_TM_PROCESS_PID:
            if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, ctx->pid, &dtb) )
                return VMI_FAILURE;
            break;
        case VMI_TM_PROCESS_DTB:
            dtb = ctx->dtb;
            break;
        default:
            dbprint(VMI_DEBUG_MISC, "sym2v only supported in a virtual context!\n");
            return VMI_FAILURE;
    };

    status = sym_cache_get(vmi, ctx->addr, dtb, symbol, &address);
    if ( VMI_FAILURE == status) {
        if (vmi->os_interface && vmi->os_interface->os_usym2rva) {
            status  = vmi->os_interface->os_usym2rva(vmi, ctx, symbol, &rva);
            if ( VMI_SUCCESS == status ) {
                address = canonical_addr(ctx->addr + rva);
                sym_cache_set(vmi, ctx->addr, dtb, symbol, address);
            }
        }
    }

    *vaddr = address;
    return status;
}

/* convert an RVA into a symbol */
const char*
vmi_translate_v2sym(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t rva)
{
    char *ret = NULL;
    addr_t dtb = 0;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !ctx)
        return NULL;
#endif

    switch (ctx->translate_mechanism) {
        case VMI_TM_PROCESS_PID:
            if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, ctx->pid, &dtb) )
                return NULL;
            break;
        case VMI_TM_PROCESS_DTB:
            dtb = ctx->dtb;
            break;
        default:
            dbprint(VMI_DEBUG_MISC, "v2sym only supported in a virtual context!\n");
            return NULL;
    };

    if (VMI_FAILURE == rva_cache_get(vmi, ctx->addr, dtb, rva, &ret)) {
        if (vmi->os_interface && vmi->os_interface->os_v2sym) {
            ret = vmi->os_interface->os_v2sym(vmi, rva, ctx);
        }

        if (ret) {
            rva_cache_set(vmi, ctx->addr, dtb, rva, ret);
        }
    }

    return ret;
}

/* convert a VA into a symbol */
const char*
vmi_translate_v2ksym(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t va)
{
    char *ret = NULL;
    addr_t dtb = 0;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !ctx)
        return NULL;
#endif

    switch (ctx->translate_mechanism) {
        case VMI_TM_PROCESS_PID:
            if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, ctx->pid, &dtb) )
                return NULL;
            break;
        case VMI_TM_PROCESS_DTB:
            dtb = ctx->dtb;
            break;
        default:
            dbprint(VMI_DEBUG_MISC, "v2ksym only supported in a virtual context!\n");
            return NULL;
    };

    if (VMI_FAILURE == rva_cache_get(vmi, ctx->addr, dtb, va, &ret)) {
        if (vmi->os_interface && vmi->os_interface->os_v2ksym) {
            ret = vmi->os_interface->os_v2ksym(vmi, va, ctx);
        }

        if (ret) {
            rva_cache_set(vmi, ctx->addr, dtb, va, ret);
        }
    }

    return ret;
}

/* finds the address of the page global directory for a given pid */
status_t
vmi_pid_to_dtb(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t *dtb)
{
    status_t ret = VMI_FAILURE;
    addr_t _dtb = 0;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !dtb)
        return VMI_FAILURE;

    if (!vmi->os_interface)
        return VMI_FAILURE;
#endif

    if ( !pid ) {
        *dtb = vmi->kpgd;
        return VMI_SUCCESS;
    }

    ret = pid_cache_get(vmi, pid, &_dtb);
    if ( VMI_FAILURE == ret ) {
        if (vmi->os_interface->os_pid_to_pgd)
            ret = vmi->os_interface->os_pid_to_pgd(vmi, pid, &_dtb);

        if ( VMI_SUCCESS == ret )
            pid_cache_set(vmi, pid, _dtb);
    }

    *dtb = _dtb;
    return ret;
}

/* finds the pid for a given dtb */
status_t
vmi_dtb_to_pid(
    vmi_instance_t vmi,
    addr_t dtb,
    vmi_pid_t *pid)
{
    status_t ret = VMI_FAILURE;
    vmi_pid_t _pid = -1;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !pid)
        return VMI_FAILURE;
#endif

    if (vmi->os_interface && vmi->os_interface->os_pgd_to_pid)
        ret = vmi->os_interface->os_pgd_to_pid(vmi, dtb, &_pid);

    *pid = _pid;
    return ret;
}

void* vmi_read_page (vmi_instance_t vmi, addr_t frame_num)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return NULL;
#endif

    return driver_read_page(vmi, frame_num);
}

GSList* vmi_get_va_pages(vmi_instance_t vmi, addr_t dtb)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return NULL;

    if (!vmi->arch_interface.get_pages[vmi->page_mode]) {
        dbprint(VMI_DEBUG_PTLOOKUP, "Invalid or not supported paging mode during get_va_pages\n");
        return NULL;
    }
#endif

    return vmi->arch_interface.get_pages[vmi->page_mode](vmi, 0, 0, dtb);
}

GSList* vmi_get_nested_va_pages(vmi_instance_t vmi, addr_t npt, page_mode_t npm, addr_t pt, page_mode_t pm)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return NULL;

    if (valid_npm(npm) && !npt)
        return NULL;

    if (!valid_pm(pm)) {
        dbprint(VMI_DEBUG_PTLOOKUP, "Invalid or not supported paging mode during get_va_pages\n");
        return NULL;
    }
#endif

    return vmi->arch_interface.get_pages[pm](vmi, npt, npm, pt);
}

status_t
vmi_pagetable_lookup(
    vmi_instance_t vmi,
    addr_t pt,
    addr_t vaddr,
    addr_t *paddr)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !paddr)
        return VMI_FAILURE;
#endif

    return vmi_pagetable_lookup_cache(vmi, pt, vaddr, paddr);
}

status_t vmi_nested_pagetable_lookup (
    vmi_instance_t vmi,
    addr_t npt,
    page_mode_t npm,
    addr_t pt,
    page_mode_t pm,
    addr_t vaddr,
    addr_t *paddr,
    addr_t *naddr)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !paddr)
        return VMI_FAILURE;

    if (valid_npm(npm) && !naddr)
        return VMI_FAILURE;

    if (!valid_pm(pm)) {
        errprint("Invalid paging mode during vmi_nested_pagetable_lookup: %i\n", pm);
        return VMI_FAILURE;
    }
#endif

    /* check if entry exists in the cache */
    if (VMI_SUCCESS == v2p_cache_get(vmi, vaddr, pt, npt, paddr)) {

        /* verify that address is still valid */
        uint8_t value = 0;
        if (VMI_SUCCESS == vmi_read_8_pa(vmi, *paddr, &value)) {
            if (valid_npm(npm)) {
                *naddr = *paddr;
                *paddr = ~0ull;
            }

            return VMI_SUCCESS;
        }
    }

    page_info_t info;

    if (VMI_FAILURE == vmi->arch_interface.lookup[pm](vmi, npt, npm, pt, vaddr, &info))
        return VMI_FAILURE;

    *paddr = info.paddr;

    if (valid_npm(npm)) {
        *naddr = info.naddr;
        v2p_cache_set(vmi, vaddr, pt, npt, info.naddr);
        return VMI_SUCCESS;
    }

    v2p_cache_set(vmi, vaddr, pt, 0, info.paddr);
    return VMI_SUCCESS;
}


/*
 * Return a status when page_info is not needed, but also use the cache,
 * which vmi_pagetable_lookup_extended() does not do.
 *
 * TODO: Should this eventually replace vmi_pagetable_lookup() in the API?
 */
status_t vmi_pagetable_lookup_cache(
    vmi_instance_t vmi,
    addr_t pt,
    addr_t vaddr,
    addr_t *paddr)
{
    status_t ret = VMI_FAILURE;
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !paddr)
        return ret;

    if (!valid_pm(vmi->page_mode))
        return ret;
#endif

    page_info_t info = {
        .vaddr = vaddr,
        .pt = pt,
        .pm = vmi->page_mode
    };

    *paddr = 0;

    /* check if entry exists in the cache */
    if (VMI_SUCCESS == v2p_cache_get(vmi, vaddr, pt, 0, paddr)) {

        /* verify that address is still valid */
        uint8_t value = 0;

        if (VMI_SUCCESS == vmi_read_8_pa(vmi, *paddr, &value)) {
            return VMI_SUCCESS;
        } else {
            if ( VMI_FAILURE == v2p_cache_del(vmi, vaddr, 0, pt) )
                return VMI_FAILURE;
        }
    }

    if (vmi->arch_interface.lookup[vmi->page_mode]) {
        ret = vmi->arch_interface.lookup[vmi->page_mode](vmi, 0, 0, pt, vaddr, &info);
    } else {
        errprint("Invalid paging mode during vmi_pagetable_lookup\n");
        ret = VMI_FAILURE;
    }

    /* add this to the cache */
    if (ret == VMI_SUCCESS) {
        *paddr = info.paddr;
        v2p_cache_set(vmi, vaddr, pt, 0, info.paddr);
    }
    return ret;
}


status_t vmi_pagetable_lookup_extended(
    vmi_instance_t vmi,
    addr_t pt,
    addr_t vaddr,
    page_info_t *info)
{
    status_t ret = VMI_FAILURE;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !info)
        return ret;

    if (!valid_pm(vmi->page_mode))
        return ret;
#endif

    memset(info, 0, sizeof(page_info_t));
    info->vaddr = vaddr;
    info->pt = pt;
    info->pm = vmi->page_mode;

    if (vmi->arch_interface.lookup[vmi->page_mode]) {
        ret = vmi->arch_interface.lookup[vmi->page_mode](vmi, 0, 0, pt, vaddr, info);
    } else {
        errprint("Invalid paging mode during vmi_pagetable_lookup\n");
    }

    /* add this to the cache */
    if (ret == VMI_SUCCESS) {
        v2p_cache_set(vmi, vaddr, pt, 0, info->paddr);
    }
    return ret;
}

/* expose virtual to physical mapping for kernel space via api call */
status_t
vmi_translate_kv2p(
    vmi_instance_t vmi,
    addr_t virt_address,
    addr_t *paddr)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !paddr)
        return VMI_FAILURE;

    if (!vmi->kpgd) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--early bail on v2p lookup because the kernel page global directory is unknown\n");
        return VMI_FAILURE;
    }
#endif

    return vmi_pagetable_lookup(vmi, vmi->kpgd, virt_address, paddr);
}

status_t
vmi_translate_uv2p(
    vmi_instance_t vmi,
    addr_t virt_address,
    vmi_pid_t pid,
    addr_t *paddr)
{
    status_t ret = VMI_FAILURE;
    addr_t dtb = 0;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi || !paddr) {
        return VMI_FAILURE;
    }
#endif

    if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, pid, &dtb) || !dtb ) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--early bail on v2p lookup because dtb not found\n");
        return VMI_FAILURE;
    }

    ret = vmi_pagetable_lookup_cache(vmi, dtb, virt_address, paddr);

    if ( VMI_FAILURE == ret) {
        if ( VMI_FAILURE == pid_cache_del(vmi, pid) )
            return VMI_FAILURE;

        ret = vmi_pid_to_dtb(vmi, pid, &dtb);
        if (VMI_SUCCESS == ret) {
            page_info_t info = {0};
            /* _extended() skips the v2p_cache lookup that must have already failed */
            ret = vmi_pagetable_lookup_extended(vmi, dtb, virt_address, &info);

            if ( VMI_SUCCESS == ret )
                *paddr = info.paddr;
        }
    }

    return ret;
}

const char *
vmi_get_linux_sysmap(
    vmi_instance_t vmi)
{
    linux_instance_t linux_instance = NULL;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return NULL;

    if (VMI_OS_LINUX != vmi->os_type)
        return NULL;

    if (!vmi->os_data)
        return NULL;
#endif

    linux_instance = vmi->os_data;

    return linux_instance->sysmap;

}

const char *
vmi_get_freebsd_sysmap(
    vmi_instance_t vmi)
{
    freebsd_instance_t freebsd_instance = NULL;

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return NULL;

    if (VMI_OS_FREEBSD != vmi->os_type)
        return NULL;

    if (!vmi->os_data)
        return NULL;
#endif

    freebsd_instance = vmi->os_data;

    return freebsd_instance->sysmap;

}

const char *
vmi_get_rekall_path(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return NULL;
#endif

#ifdef ENABLE_JSON_PROFILES
    return vmi->json.path;
#else
    return NULL;
#endif
}

const char *
vmi_get_os_profile_path(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return NULL;
#endif

#ifdef ENABLE_JSON_PROFILES
    if ( vmi->json.path )
        return vmi->json.path;
#endif

#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->os_data)
        return NULL;
#endif

    switch (vmi->os_type) {
        case VMI_OS_LINUX: {
            linux_instance_t linux_instance = vmi->os_data;
            return linux_instance->sysmap;
        }
        case VMI_OS_FREEBSD: {
            freebsd_instance_t freebsd_instance = vmi->os_data;
            return freebsd_instance->sysmap;
        }
        default:
            break;
    };

    return NULL;
}

void
vmi_pidcache_add(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t dtb)
{
    if (!vmi)
        return;

    return pid_cache_set(vmi, pid, dtb);
}

void
vmi_pidcache_flush(
    vmi_instance_t vmi)
{
    if (!vmi)
        return;

    return pid_cache_flush(vmi);
}

void
vmi_symcache_add(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    char *sym,
    addr_t va)
{
    if (!vmi)
        return;

    return sym_cache_set(vmi, base_addr, pid, sym, va);
}

void
vmi_symcache_flush(
    vmi_instance_t vmi)
{
    if (!vmi)
        return;

    return sym_cache_flush(vmi);
}

void
vmi_rvacache_add(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    addr_t rva,
    char *sym)
{
    addr_t pgd = 0;

    if (!vmi)
        return;

    if (VMI_SUCCESS != vmi_pid_to_dtb(vmi, pid, &pgd)) {
        dbprint(VMI_DEBUG_SYMCACHE, "--SYM cache failed to find base for PID %u\n", pid);
        return;
    }

    return rva_cache_set(vmi, base_addr, pgd, rva, sym);
}

void
vmi_rvacache_flush(
    vmi_instance_t vmi)
{
    if (!vmi)
        return;

    return rva_cache_flush(vmi);
}

void
vmi_v2pcache_add(
    vmi_instance_t vmi,
    addr_t va,
    addr_t pt,
    addr_t pa)
{
    if (!vmi)
        return;

    return v2p_cache_set(vmi, va, pt, 0, pa);
}

void
vmi_v2pcache_nested_add(
    vmi_instance_t vmi,
    addr_t va,
    addr_t pt,
    addr_t npt,
    addr_t pa)
{
    if (!vmi)
        return;

    return v2p_cache_set(vmi, va, pt, npt, pa);
}

void
vmi_v2pcache_flush(
    vmi_instance_t vmi,
    addr_t pt)
{
    if (!vmi)
        return;

    return v2p_cache_flush(vmi, pt, 0);
}

void
vmi_v2pcache_nested_flush(
    vmi_instance_t vmi,
    addr_t pt,
    addr_t npt)
{
    if (!vmi)
        return;

    return v2p_cache_flush(vmi, pt, npt);
}

void
vmi_pagecache_flush(
    vmi_instance_t vmi)
{
    if (!vmi)
        return;

    return memory_cache_flush(vmi);
}

status_t vmi_read_disk(
    vmi_instance_t vmi,
    const char *device_id,
    uint64_t offset,
    uint64_t count,
    void *buffer)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return 0;

#endif

    if ( vmi->mode != VMI_XEN)
        return VMI_FAILURE;
    if ( VMI_FAILURE == driver_read_disk(vmi, device_id, offset, count, buffer) )
        return VMI_FAILURE;

    return VMI_SUCCESS;
}

char **vmi_get_disks(
    vmi_instance_t vmi,
    unsigned int *num)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi)
        return 0;

#endif

    if ( vmi->mode != VMI_XEN)
        return NULL;
    return driver_get_disks(vmi, num);
}

status_t vmi_disk_is_bootable(
    vmi_instance_t vmi,
    const char *device_id,
    bool *bootable)
{
    if ( vmi->mode != VMI_XEN)
        return VMI_FAILURE;
    if ( VMI_FAILURE == driver_disk_is_bootable(vmi, device_id, bootable) )
        return VMI_FAILURE;

    return VMI_SUCCESS;
}
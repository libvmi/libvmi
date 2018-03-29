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

/* NB: Necessary for windows specific API functions */
#include "os/windows/windows.h"

uint8_t vmi_get_address_width(
    vmi_instance_t vmi)
{
    if (!vmi)
        return 0;

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
    return (NULL == vmi) ? VMI_OS_UNKNOWN : vmi->os_type;
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

    if (!vmi)
        return VMI_OS_WINDOWS_NONE;

    if (VMI_OS_WINDOWS != vmi->os_type)
        return VMI_OS_WINDOWS_NONE;

    if (!vmi->os_data) {
        return VMI_OS_WINDOWS_NONE;
    }

    windows_instance = vmi->os_data;

    if (!windows_instance->version || windows_instance->version == VMI_OS_WINDOWS_UNKNOWN) {
        addr_t kdbg = windows_instance->ntoskrnl + windows_instance->kdbg_offset;
        windows_instance->version = find_windows_version(vmi, kdbg);
    }
    return windows_instance->version;
#endif
}

const char *
vmi_get_winver_str(
    vmi_instance_t vmi)
{
    if (!vmi)
        return "VMI_OS_WINDOWS_NONE";

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
    if (!vmi)
        return VMI_FAILURE;

    if ( !vmi->os_interface || !vmi->os_interface->os_get_offset )
        return VMI_FAILURE;

    return vmi->os_interface->os_get_offset(vmi, offset_name, offset);
}

status_t
vmi_get_kernel_struct_offset(
    vmi_instance_t vmi,
    const char* symbol,
    const char* member,
    addr_t *addr)
{
    if (!vmi || !addr)
        return 0;

    return vmi->os_interface->os_get_kernel_struct_offset(vmi, symbol, member, addr);
}

uint64_t
vmi_get_memsize(
    vmi_instance_t vmi)
{
    if (!vmi)
        return 0;

    if ( VMI_FAILURE == driver_get_memsize(vmi, &vmi->allocated_ram_size, &vmi->max_physical_address) )
        return 0;

    return vmi->allocated_ram_size;
}

addr_t
vmi_get_max_physical_address(
    vmi_instance_t vmi)
{
    if (!vmi)
        return 0;

    if ( VMI_FAILURE == driver_get_memsize(vmi, &vmi->allocated_ram_size, &vmi->max_physical_address) )
        return 0;

    return vmi->max_physical_address;
}

unsigned int
vmi_get_num_vcpus(
    vmi_instance_t vmi)
{
    if (!vmi)
        return 0;

    return vmi->num_vcpus;
}

status_t
vmi_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
    if (!vmi)
        return VMI_FAILURE;

    return driver_get_vcpureg(vmi, value, reg, vcpu);
}

status_t
vmi_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
    if (!vmi || !regs)
        return VMI_FAILURE;

    return driver_get_vcpuregs(vmi, regs, vcpu);
}

status_t
vmi_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu)
{
    if (!vmi)
        return VMI_FAILURE;

    return driver_set_vcpureg(vmi, value, reg, vcpu);
}

status_t
vmi_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
    if (!vmi || !regs)
        return VMI_FAILURE;

    return driver_set_vcpuregs(vmi, regs, vcpu);
}

status_t
vmi_pause_vm(
    vmi_instance_t vmi)
{
    if (!vmi)
        return VMI_FAILURE;

    return driver_pause_vm(vmi);
}

status_t
vmi_resume_vm(
    vmi_instance_t vmi)
{
    if (!vmi)
        return VMI_FAILURE;

    return driver_resume_vm(vmi);
}

char *
vmi_get_name(
    vmi_instance_t vmi)
{
    /* memory for name is allocated at the driver level */
    char *name = NULL;

    if (!vmi)
        return NULL;

    if (VMI_FAILURE == driver_get_name(vmi, &name)) {
        return NULL;
    } else {
        return name;
    }
}

const char *
vmi_get_rekall_path(
    vmi_instance_t vmi)
{
    if (!vmi)
        return NULL;

    switch (vmi_get_ostype(vmi)) {
        case VMI_OS_LINUX:
            return (const char*)((linux_instance_t)vmi->os_data)->rekall_profile;
        case VMI_OS_WINDOWS:
            return (const char*)((windows_instance_t)vmi->os_data)->rekall_profile;
        default:
            return NULL;
    }
}

uint64_t
vmi_get_vmid(
    vmi_instance_t vmi)
{
    uint64_t domid = VMI_INVALID_DOMID;

    if (!vmi)
        return 0;

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

    if (!vmi || !symbol || !vaddr)
        return VMI_FAILURE;

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

    if (!vmi || !ctx || !symbol || !vaddr)
        return VMI_FAILURE;

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

    if (!vmi || !ctx)
        return NULL;

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

    if (!vmi || !ctx)
        return NULL;

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

    if (!vmi || !dtb)
        return VMI_FAILURE;

    if (!vmi->os_interface)
        return VMI_FAILURE;

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

    if (!vmi || !pid)
        return VMI_FAILURE;

    if (vmi->os_interface && vmi->os_interface->os_pgd_to_pid)
        ret = vmi->os_interface->os_pgd_to_pid(vmi, dtb, &_pid);

    *pid = _pid;
    return ret;
}

void* vmi_read_page (vmi_instance_t vmi, addr_t frame_num)
{
    if (!vmi)
        return NULL;

    return driver_read_page(vmi, frame_num);
}

GSList* vmi_get_va_pages(vmi_instance_t vmi, addr_t dtb)
{
    if (!vmi)
        return NULL;

    if (vmi->arch_interface && vmi->arch_interface->get_va_pages) {
        return vmi->arch_interface->get_va_pages(vmi, dtb);
    } else {
        dbprint(VMI_DEBUG_PTLOOKUP, "Invalid or not supported paging mode during get_va_pages\n");
        return NULL;
    }
}

status_t
vmi_pagetable_lookup(
    vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    addr_t *paddr)
{
    if (!vmi || !paddr)
        return VMI_FAILURE;

    return vmi_pagetable_lookup_cache(vmi, dtb, vaddr, paddr);
}

/*
 * Return a status when page_info is not needed, but also use the cache,
 * which vmi_pagetable_lookup_extended() does not do.
 *
 * TODO: Should this eventually replace vmi_pagetable_lookup() in the API?
 */
status_t vmi_pagetable_lookup_cache(
    vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    addr_t *paddr)
{
    status_t ret = VMI_FAILURE;
    page_info_t info = { .vaddr = vaddr,
                         .dtb = dtb
                       };

    if (!vmi || !paddr) return ret;

    *paddr = 0;

    /* check if entry exists in the cache */
    if (VMI_SUCCESS == v2p_cache_get(vmi, vaddr, dtb, paddr)) {

        /* verify that address is still valid */
        uint8_t value = 0;

        if (VMI_SUCCESS == vmi_read_8_pa(vmi, *paddr, &value)) {
            return VMI_SUCCESS;
        } else {
            if ( VMI_FAILURE == v2p_cache_del(vmi, vaddr, dtb) )
                return VMI_FAILURE;
        }
    }

    if (vmi->arch_interface && vmi->arch_interface->v2p) {
        ret = vmi->arch_interface->v2p(vmi, dtb, vaddr, &info);
    } else {
        errprint("Invalid paging mode during vmi_pagetable_lookup\n");
        ret = VMI_FAILURE;
    }

    /* add this to the cache */
    if (ret == VMI_SUCCESS) {
        *paddr = info.paddr;
        v2p_cache_set(vmi, vaddr, dtb, info.paddr);
    }
    return ret;
}


status_t vmi_pagetable_lookup_extended(
    vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    page_info_t *info)
{
    status_t ret = VMI_FAILURE;

    if (!vmi || !info) return ret;

    memset(info, 0, sizeof(page_info_t));
    info->vaddr = vaddr;
    info->dtb = dtb;

    if (vmi->arch_interface && vmi->arch_interface->v2p) {
        ret = vmi->arch_interface->v2p(vmi, dtb, vaddr, info);
    } else {
        errprint("Invalid paging mode during vmi_pagetable_lookup\n");
    }

    /* add this to the cache */
    if (ret == VMI_SUCCESS) {
        v2p_cache_set(vmi, vaddr, dtb, info->paddr);
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
    if (!vmi || !paddr)
        return VMI_FAILURE;

    if (!vmi->kpgd) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--early bail on v2p lookup because the kernel page global directory is unknown\n");
        return VMI_FAILURE;
    }

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

    if (!vmi || !paddr) {
        return VMI_FAILURE;
    }

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

    if (!vmi) {
        return NULL;
    }

    if (VMI_OS_LINUX != vmi->os_type) {
        return NULL;
    }

    if (!vmi->os_data) {
        return NULL;
    }

    linux_instance = vmi->os_data;

    return linux_instance->sysmap;

}

const char *
vmi_get_freebsd_sysmap(
    vmi_instance_t vmi)
{
    freebsd_instance_t freebsd_instance = NULL;

    if (!vmi) {
        return NULL;
    }

    if (VMI_OS_FREEBSD != vmi->os_type) {
        return NULL;
    }

    if (!vmi->os_data) {
        return NULL;
    }

    freebsd_instance = vmi->os_data;

    return freebsd_instance->sysmap;

}

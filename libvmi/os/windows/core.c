
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
#include "libvmi/peparse.h"
#include "os/windows/windows.h"
#include "driver/driver_wrapper.h"
#include "config/config_parser.h"

// See http://en.wikipedia.org/wiki/Windows_NT
static inline
win_ver_t ntbuild2version(uint16_t ntbuildnumber)
{
    switch (ntbuildnumber) {
        case 2195:
            return VMI_OS_WINDOWS_2000;
        case 2600:
        case 3790:
            return VMI_OS_WINDOWS_XP;
        case 6000:
        case 6001:
        case 6002:
            return VMI_OS_WINDOWS_VISTA;
        case 7600:
        case 7601:
            return VMI_OS_WINDOWS_7;
        case 9200:
        case 9600:
            return VMI_OS_WINDOWS_8;
        case 10240:
        case 10586:
        case 14393:
        case 18432:
            return VMI_OS_WINDOWS_10;
        default:
            break;
    }
    return VMI_OS_WINDOWS_UNKNOWN;
};

static inline
win_ver_t pe2version(vmi_instance_t vmi, addr_t kernbase_pa)
{
    // Examine the PE header to determine the version
    uint16_t major_os_version = 0;
    uint16_t minor_os_version = 0;
    uint16_t optional_header_type = 0;
    struct optional_header_pe32 *oh32 = NULL;
    struct optional_header_pe32plus *oh32plus = NULL;
    uint8_t pe[VMI_PS_4KB];
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_NONE,
        .addr = kernbase_pa
    };

    if ( VMI_FAILURE == peparse_get_image(vmi, &ctx, VMI_PS_4KB, pe) ) {
        return VMI_OS_WINDOWS_NONE;
    }

    peparse_assign_headers(pe, NULL, NULL, &optional_header_type, NULL, &oh32, &oh32plus);

    switch (optional_header_type) {
        case IMAGE_PE32_MAGIC:
            major_os_version=oh32->major_os_version;
            minor_os_version=oh32->minor_os_version;
            break;
        case IMAGE_PE32_PLUS_MAGIC:
            major_os_version=oh32plus->major_os_version;
            minor_os_version=oh32plus->minor_os_version;
            break;
        default:
            return VMI_OS_WINDOWS_NONE;
    };

    switch (major_os_version) {
        case 3:
        case 4:
            // This is Windows NT but it is not supported
            return VMI_OS_WINDOWS_NONE;
        case 5:
            switch (minor_os_version) {
                case 0:
                    return VMI_OS_WINDOWS_2000;
                case 1:
                    return VMI_OS_WINDOWS_XP;
                case 2:
                    return VMI_OS_WINDOWS_2003;
            };
        case 6:
            switch (minor_os_version) {
                case 0:
                    return VMI_OS_WINDOWS_VISTA;
                case 1:
                    return VMI_OS_WINDOWS_7;
                case 2:
                    return VMI_OS_WINDOWS_8;
            };
        case 10:
            switch (minor_os_version) {
                case 0:
                    return VMI_OS_WINDOWS_10;
            };
    };

    return VMI_OS_WINDOWS_NONE;
}

static inline
status_t check_pdbase_offset(vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;
    windows_instance_t windows = vmi->os_data;

    if (!windows->pdbase_offset) {
        if (windows->rekall_profile) {
            if (VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "_KPROCESS", "DirectoryTableBase", &windows->pdbase_offset)) {
                goto done;
            }
        } else {
            dbprint(VMI_DEBUG_MISC, "--win_pdbase is undefined\n");
            goto done;
        }
    }

    ret = VMI_SUCCESS;

done:
    return ret;
}

addr_t
get_ntoskrnl_base(
    vmi_instance_t vmi,
    addr_t page_paddr)
{
    addr_t ret = 0;
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_NONE,
        .addr = page_paddr
    };

    for (; ctx.addr + VMI_PS_4KB < vmi->max_physical_address; ctx.addr += VMI_PS_4KB) {

        uint8_t page[VMI_PS_4KB];
        if (VMI_FAILURE == peparse_get_image(vmi, &ctx, VMI_PS_4KB, page))
            continue;

        struct pe_header *pe_header = NULL;
        struct dos_header *dos_header = NULL;
        void *optional_pe_header = NULL;
        uint16_t optional_header_type = 0;
        struct export_table et;

        peparse_assign_headers(page, &dos_header, &pe_header, &optional_header_type, &optional_pe_header, NULL, NULL);
        addr_t export_header_offset =
            peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_EXPORT, &optional_header_type, optional_pe_header, NULL, NULL);

        if (!export_header_offset || ctx.addr + export_header_offset >= vmi->max_physical_address)
            continue;

        if ( VMI_SUCCESS == vmi_read_pa(vmi, ctx.addr + export_header_offset, sizeof(struct export_table), &et, NULL) ) {
            if ( !(et.export_flags || !et.name) && ctx.addr + et.name + 12 >= vmi->max_physical_address)
                continue;

            unsigned char name[13] = {0};
            if ( VMI_FAILURE == vmi_read_pa(vmi, ctx.addr + et.name, 12, name, NULL) )
                continue;

            if (!strcmp("ntoskrnl.exe", (char*)name)) {
                ret = ctx.addr;
                break;
            }
        } else {
            continue;
        }
    }

    return ret;
}

/* Tries to determine the page mode based on the kpgd found via heuristics */
static status_t
find_page_mode(
    vmi_instance_t vmi)
{

    status_t ret = VMI_FAILURE;
    windows_instance_t windows = vmi->os_data;
    uint32_t mask = ~0;

    if (!windows) {
        errprint("Windows functions not initialized in %s\n", __FUNCTION__);
        return VMI_FAILURE;
    }

    if (!windows->ntoskrnl || !windows->ntoskrnl_va) {
        errprint("Windows kernel virtual and physical address required for determining page mode\n");
        return VMI_FAILURE;
    }

    if (!vmi->kpgd) {
        errprint("Windows kernel directory table base not set, can't determine page mode\n");
        return VMI_FAILURE;
    }

    dbprint(VMI_DEBUG_MISC, "--trying VMI_PM_LEGACY\n");
    vmi->page_mode = VMI_PM_LEGACY;

    /* As the size of vmi->kpgd is 64-bit, we mask it to be 32-bit here */
    if (VMI_SUCCESS == arch_init(vmi)) {
        addr_t test = 0;
        if ( VMI_SUCCESS == vmi_pagetable_lookup(vmi, (vmi->kpgd & mask), windows->ntoskrnl_va, &test) &&
                test == windows->ntoskrnl) {
            vmi->kpgd &= mask;
            goto found_pm;
        }
    }

    dbprint(VMI_DEBUG_MISC, "--trying VMI_PM_PAE\n");
    vmi->page_mode = VMI_PM_PAE;

    /* As the size of vmi->kpgd is 64-bit, we mask it to be only 32-bit here */
    if (VMI_SUCCESS == arch_init(vmi)) {
        addr_t test = 0;
        if ( VMI_SUCCESS == vmi_pagetable_lookup(vmi, (vmi->kpgd & mask), windows->ntoskrnl_va, &test) &&
                test == windows->ntoskrnl) {
            vmi->kpgd &= mask;
            goto found_pm;
        }
    }

    dbprint(VMI_DEBUG_MISC, "--trying VMI_PM_IA32E\n");
    vmi->page_mode = VMI_PM_IA32E;

    if (VMI_SUCCESS == arch_init(vmi)) {
        addr_t test = 0;
        if ( VMI_SUCCESS == vmi_pagetable_lookup(vmi, vmi->kpgd, windows->ntoskrnl_va, &test) &&
                test == windows->ntoskrnl) {
            goto found_pm;
        }
    }

    goto done;

found_pm:
    ret = VMI_SUCCESS;

done:
    return ret;
}

/* Tries to find the kernel page directory by doing an exhaustive search
 * through the memory space for the System process.  The page directory
 * location is then pulled from this eprocess struct.
 */
static status_t
get_kpgd_method2(
    vmi_instance_t vmi)
{
    addr_t sysproc = 0;
    windows_instance_t windows = NULL;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No OS data initialized\n");
        return VMI_FAILURE;
    }

    windows = vmi->os_data;
    sysproc = windows->sysproc;

    /* get address for System process */
    if (!sysproc) {
        if ((sysproc = windows_find_eprocess(vmi, "System")) == 0) {
            dbprint(VMI_DEBUG_MISC, "--failed to find System process.\n");
            goto error_exit;
        }
        printf("LibVMI Suggestion: set win_sysproc=0x%"PRIx64" in libvmi.conf for faster startup.\n",
               sysproc);
    }
    dbprint(VMI_DEBUG_MISC, "--got PA to PsInitialSystemProcess (0x%.16"PRIx64").\n",
            sysproc);

    /* Get address for page directory (from system process).
       We are reading 64-bit value here deliberately as we might not know the page mode yet */
    if (VMI_FAILURE ==
            vmi_read_64_pa(vmi,
                           sysproc +
                           windows->pdbase_offset,
                           &vmi->kpgd)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve PD for System process\n");
        goto error_exit;
    }

    if (!vmi->kpgd) {
        dbprint(VMI_DEBUG_MISC, "--kpgd was zero\n");
        goto error_exit;
    }

    if (VMI_FAILURE ==
            vmi_read_64_pa(vmi,
                           sysproc + windows->tasks_offset,
                           &vmi->init_task)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve address of System process\n");
        goto error_exit;
    }

    vmi->init_task -= windows->tasks_offset;

    /* If the page mode is already known to be 32-bit we just mask the value here.
       If don't know the page mode yet it will be determined using heuristics in find_page_mode later. */
    switch (vmi->page_mode) {
        case VMI_PM_LEGACY:
        case VMI_PM_PAE: {
            uint32_t mask = ~0;
            vmi->kpgd &= mask;
            vmi->init_task &= mask;
            break;
        }
        default:
            break;
    }

    dbprint(VMI_DEBUG_MISC, "**set kpgd (0x%.16"PRIx64").\n", vmi->kpgd);
    dbprint(VMI_DEBUG_MISC, "**set init_task (0x%.16"PRIx64").\n", vmi->init_task);

    return VMI_SUCCESS;

error_exit:
    return VMI_FAILURE;
}

addr_t
windows_find_cr3(
    vmi_instance_t vmi)
{
    get_kpgd_method2(vmi);
    return vmi->kpgd;
}

/* Tries to find the kernel page directory using the RVA value for
 * PSInitialSystemProcess and the ntoskrnl value to lookup the System
 * process, and the extract the page directory location from this
 * eprocess struct.
 */
static status_t
get_kpgd_method1(
    vmi_instance_t vmi)
{
    addr_t sysproc = 0;
    windows_instance_t windows = NULL;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No OS data initialized\n");
        return VMI_FAILURE;
    }

    windows = vmi->os_data;

    if (VMI_FAILURE ==
            vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &sysproc)) {
        dbprint(VMI_DEBUG_MISC, "--failed to read pointer for system process\n");
        goto error_exit;
    }

    if (VMI_FAILURE == vmi_translate_kv2p(vmi, sysproc, &sysproc) )
        goto error_exit;

    dbprint(VMI_DEBUG_MISC, "--got PA to PsInitialSystemProcess (0x%.16"PRIx64").\n",
            sysproc);

    if (VMI_FAILURE ==
            vmi_read_addr_pa(vmi,
                             sysproc +
                             windows->pdbase_offset,
                             &vmi->kpgd)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve pointer for system process\n");
        goto error_exit;
    }

    if (!vmi->kpgd) {
        dbprint(VMI_DEBUG_MISC, "--kpgd was zero\n");
        goto error_exit;
    }
    dbprint(VMI_DEBUG_MISC, "**set kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    if (VMI_FAILURE ==
            vmi_read_addr_pa(vmi,
                             sysproc + windows->tasks_offset,
                             &vmi->init_task)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve address of System process\n");
        goto error_exit;
    }
    vmi->init_task -= windows->tasks_offset;
    dbprint(VMI_DEBUG_MISC, "**set init_task (0x%.16"PRIx64").\n", vmi->init_task);

    return VMI_SUCCESS;

error_exit:
    return VMI_FAILURE;
}

static status_t
get_kpgd_method0(
    vmi_instance_t vmi)
{
    addr_t sysproc_va = 0;
    addr_t sysproc_pa = 0;
    addr_t active_process_head = 0;
    windows_instance_t windows = NULL;
    vmi_pid_t pid = 4;
    size_t len = sizeof(vmi_pid_t);
    addr_t kpgd = 0;

    if (vmi->os_data == NULL) {
        errprint("VMI_ERROR: No OS data initialized\n");
        return VMI_FAILURE;
    }

    windows = vmi->os_data;

    if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &active_process_head)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve PsActiveProcessHead\n");
        goto error_exit;
    }

    dbprint(VMI_DEBUG_MISC, "--starting search from PsActiveProcessHead (0x%.16"PRIx64") using kpgd (0x%.16"PRIx64").\n",
            active_process_head, vmi->kpgd);

    sysproc_va = eprocess_list_search(vmi, active_process_head - windows->tasks_offset, windows->pid_offset, len, &pid);

    if (sysproc_va == 0) {
        dbprint(VMI_DEBUG_MISC, "--failed to find system process with pid 4\n");
        goto error_exit;
    }

    sysproc_va -= windows->tasks_offset;
    dbprint(VMI_DEBUG_MISC, "--Found System process at %lx\n", sysproc_va);
    if ( VMI_FAILURE == vmi_translate_kv2p(vmi, sysproc_va, &sysproc_pa) ) {
        dbprint(VMI_DEBUG_MISC, "--failed to translate System process\n");
        goto error_exit;
    }

    dbprint(VMI_DEBUG_MISC, "--Found System process physical address at %lx\n", sysproc_pa);

    if (VMI_FAILURE ==
            vmi_read_addr_pa(vmi,
                             sysproc_pa +
                             windows->pdbase_offset,
                             &kpgd)) {
        dbprint(VMI_DEBUG_MISC, "--failed to resolve pointer for system process\n");
        goto error_exit;
    }

    if (!kpgd) {
        dbprint(VMI_DEBUG_MISC, "--kpgd was zero\n");
        goto error_exit;
    }
    vmi->kpgd = kpgd;
    dbprint(VMI_DEBUG_MISC, "**set kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    vmi->init_task = sysproc_va;
    dbprint(VMI_DEBUG_MISC, "**set init_task (0x%.16"PRIx64").\n", vmi->init_task);

    return VMI_SUCCESS;

error_exit:
    return VMI_FAILURE;
}

status_t windows_get_kernel_struct_offset(vmi_instance_t vmi, const char* symbol, const char* member, addr_t *addr)
{
    windows_instance_t windows = vmi->os_data;
    return rekall_profile_symbol_to_rva(windows->rekall_profile,symbol,member,addr);
}

status_t windows_get_offset(vmi_instance_t vmi, const char* offset_name, addr_t *offset)
{
    const size_t max_length = 100;
    windows_instance_t windows = vmi->os_data;

    if (windows == NULL) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        return VMI_FAILURE;
    }

    if (strncmp(offset_name, "win_tasks", max_length) == 0) {
        *offset = windows->tasks_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "win_pdbase", max_length) == 0) {
        *offset = windows->pdbase_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "win_pid", max_length) == 0) {
        *offset = windows->pid_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "win_pname", max_length) == 0) {
        if (windows->pname_offset == 0) {
            windows->pname_offset = find_pname_offset(vmi, NULL);
            if (windows->pname_offset == 0) {
                dbprint(VMI_DEBUG_MISC, "--failed to find pname_offset\n");
                return VMI_FAILURE;
            }
        }

        *offset = windows->pname_offset;
        return VMI_SUCCESS;
    }

    warnprint("Invalid offset name in windows_get_offset (%s).\n",
              offset_name);
    return VMI_FAILURE;
}

void windows_read_config_ghashtable_entries(char* key, gpointer value,
        vmi_instance_t vmi)
{

    windows_instance_t windows_instance = vmi->os_data;

    if (strncmp(key, "win_ntoskrnl", CONFIG_STR_LENGTH) == 0) {
        windows_instance->ntoskrnl = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_ntoskrnl_va", CONFIG_STR_LENGTH) == 0) {
        windows_instance->ntoskrnl_va = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_tasks", CONFIG_STR_LENGTH) == 0) {
        windows_instance->tasks_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_pdbase", CONFIG_STR_LENGTH) == 0) {
        windows_instance->pdbase_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_pid", CONFIG_STR_LENGTH) == 0) {
        windows_instance->pid_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_pname", CONFIG_STR_LENGTH) == 0) {
        windows_instance->pname_offset = *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_kdvb", CONFIG_STR_LENGTH) == 0) {
        windows_instance->kdbg_va = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_sysproc", CONFIG_STR_LENGTH) == 0) {
        windows_instance->sysproc = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_kpcr", CONFIG_STR_LENGTH) == 0) {
        windows_instance->kpcr_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_kdbg", CONFIG_STR_LENGTH) == 0) {
        windows_instance->kdbg_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "ostype", CONFIG_STR_LENGTH) == 0 || strncmp(key, "os_type", CONFIG_STR_LENGTH) == 0) {
        goto _done;
    }

    /* Deprecated way of using Rekall profiles */
    if (strncmp(key, "sysmap", CONFIG_STR_LENGTH) == 0) {
        windows_instance->rekall_profile = g_strdup((char *)value);
        goto _done;
    }

    if (strncmp(key, "rekall_profile", CONFIG_STR_LENGTH) == 0) {
        windows_instance->rekall_profile = g_strdup((char *)value);
        goto _done;
    }

    if (strncmp(key, "name", CONFIG_STR_LENGTH) == 0) {
        goto _done;
    }

    if (strncmp(key, "domid", CONFIG_STR_LENGTH) == 0) {
        goto _done;
    }

    warnprint("Invalid offset \"%s\" given for Windows target\n", key);

_done:
    return;
}

static status_t
get_kpgd_from_rekall_profile(vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;
    windows_instance_t windows = vmi->os_data;
    addr_t sysproc_pointer_rva = 0;
    addr_t sysproc_pdbase_addr = 0;

    /* The kernel base and the pdbase offset should have already been found
     * and vmi->kpgd should be holding a CR3 value */
    if ( !windows->rekall_profile || !windows->ntoskrnl || !windows->pdbase_offset || !vmi->kpgd )
        return ret;

    dbprint(VMI_DEBUG_MISC, "**Getting kernel page directory from Rekall profile\n");

    if ( !windows->sysproc ) {
        ret = rekall_profile_symbol_to_rva(windows->rekall_profile, "PsInitialSystemProcess", NULL, &sysproc_pointer_rva);
        if ( VMI_FAILURE == ret )
            return ret;

        // try to find _physical_ address of Initial system process pointer
        if ( VMI_FAILURE == vmi_pagetable_lookup(vmi, vmi->kpgd, windows->ntoskrnl_va + sysproc_pointer_rva, &sysproc_pdbase_addr) )
            return ret;

        // read _virtual_ address of Initial system process
        ret = vmi_read_addr_pa(vmi, sysproc_pdbase_addr, &windows->sysproc);
        if ( VMI_FAILURE == ret )
            return ret;

        dbprint(VMI_DEBUG_MISC, "**Found PsInitialSystemProcess at 0x%lx\n", windows->sysproc);
    }

    if ( VMI_FAILURE == vmi_pagetable_lookup(vmi, vmi->kpgd, windows->sysproc + windows->pdbase_offset, &sysproc_pdbase_addr) )
        return VMI_FAILURE;

    ret = vmi_read_addr_pa(vmi, sysproc_pdbase_addr, &vmi->kpgd);
    if ( ret == VMI_SUCCESS && vmi->kpgd )
        return VMI_SUCCESS;

    return VMI_FAILURE;
}

static status_t
init_from_rekall_profile_real(vmi_instance_t vmi, reg_t kpcr_register_to_use)
{
    status_t ret = VMI_FAILURE;
    windows_instance_t windows = vmi->os_data;
    dbprint(VMI_DEBUG_MISC, "**Trying to init from Rekall profile\n");

    reg_t kpcr = 0;
    addr_t kpcr_rva = 0, int0_rva = 0;
    reg_t lstar=0, cstar=0;
    addr_t kisystemcall64shadow=0, kisystemcall32shadow=0;
    addr_t ntbaseaddress=0, ntbaseaddress_chk=0;

    if (kpcr_register_to_use) {
        dbprint(VMI_DEBUG_MISC, "** Trying kpcr_register_to_use to get KPCR.\n");
        if (VMI_FAILURE == driver_get_vcpureg(vmi, &kpcr, kpcr_register_to_use, 0)) {
            dbprint(VMI_DEBUG_MISC, "** driver_get_vcpureg(..) failed.\n");
            goto done;
        }

        if (VMI_SUCCESS == rekall_profile_symbol_to_rva(windows->rekall_profile, "KiInitialPCR", NULL, &kpcr_rva)) {
            if ( kpcr < kpcr_rva ) { // Zero offset seems ok. Maybe negative will work too? ;)
                dbprint(VMI_DEBUG_MISC, "**vCPU0 doesn't seem to have KiInitialPCR mapped, (kpcr < kpcr_rva) (KiInitialPCR) can't init from Rekall profile. Kpcr=0x%" PRIx64 "kpcr_rva=0x%" PRIx64 "\n", kpcr, kpcr_rva);
                goto done;
            }

            if (vmi->page_mode == VMI_PM_IA32E && kpcr < 0xffff800000000000) { // We are in 64bit user mode, this is not KPCR
                dbprint(VMI_DEBUG_MISC, "**Error while init from Rekall profile. Getting KPCR from user mode or just after syscall before 'swapgs'.\n");
                dbprint(VMI_DEBUG_MISC, "**vCPU0 doesn't seem to have KiInitialPCR mapped, can't init from Rekall profile. Kpcr=0x%" PRIx64 ", kpcr_rva=0x%" PRIx64 "\n", kpcr, kpcr_rva);
                goto done;
            }

            // If the Rekall profile has KiInitialPCR we have Win 7+
            windows->ntoskrnl_va = kpcr - kpcr_rva;
            if ( VMI_FAILURE == vmi_translate_kv2p(vmi, windows->ntoskrnl_va, &windows->ntoskrnl) )
                goto done;
            //Get kernel base address using cstar/lstar and KiSystemCall32Shadow / KiSystemCall64Shadow
        } else if ( VMI_SUCCESS == rekall_profile_symbol_to_rva(windows->rekall_profile, "KiSystemCall64Shadow", NULL, &kisystemcall64shadow) ) {

            if (VMI_FAILURE == vmi_get_vcpureg(vmi, &lstar, MSR_LSTAR, 0)) {
                errprint("Error reading MSR_LSTAR\n");
                goto done;
            }

            if (VMI_FAILURE == vmi_get_vcpureg(vmi, &cstar, MSR_CSTAR, 0)) {
                errprint("Error reading MSR_CSTAR\n");
                goto done;
            }

            if (VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "KiSystemCall32Shadow", NULL, &kisystemcall32shadow)) {
                errprint("Error retrieving rva of KiSystemCall32Shadow\n");
                goto done;

            }

            ntbaseaddress = lstar - kisystemcall64shadow;
            ntbaseaddress_chk = cstar - kisystemcall32shadow;


            if (ntbaseaddress != ntbaseaddress_chk) {
                errprint("Error calculating NT base address\n");
                goto done;
            }


            windows->ntoskrnl_va = ntbaseaddress;

            if ( VMI_FAILURE == vmi_translate_kv2p(vmi, windows->ntoskrnl_va, &windows->ntoskrnl) )
                goto done;

        } else if ( VMI_SUCCESS == rekall_profile_symbol_to_rva(windows->rekall_profile, "KiDivideErrorFault", NULL, &int0_rva) ) {
            reg_t idt = 0;
            uint32_t int0_high = 0;
            uint16_t int0_low = 0, int0_middle = 0;

            // Some Windows10+ rekall profiles don't have KiInitialPCR defined so we use the IDT route
            // For the layout of the IDT entry see http://wiki.osdev.org/Interrupt_Descriptor_Table
            if (VMI_FAILURE == driver_get_vcpureg(vmi, &idt, IDTR_BASE, 0))
                goto done;
            if (VMI_FAILURE == vmi_read_16_va(vmi, idt, 0, &int0_low))
                goto done;
            if (VMI_FAILURE == vmi_read_16_va(vmi, idt + 6, 0, &int0_middle))
                goto done;
            if (VMI_PM_IA32E == vmi->page_mode && VMI_FAILURE == vmi_read_32_va(vmi, idt + 8, 0, &int0_high))
                goto done;

            windows->ntoskrnl_va = (((uint64_t)int0_high << 32) | ((uint64_t)int0_middle << 16) | int0_low) - int0_rva;
            if ( VMI_FAILURE == vmi_translate_kv2p(vmi, windows->ntoskrnl_va, &windows->ntoskrnl) )
                goto done;
        }

        if (!windows->ntoskrnl && kpcr == 0x00000000ffdff000) {
            // If we are in live mode and still don't have the kernel base the KPCR has to be
            // at this VA (XP/Vista) and the KPCR trick [1] is still valid.
            // [1] http://moyix.blogspot.de/2008/04/finding-kernel-global-variables-in.html
            addr_t kdvb = 0, kdvb_offset = 0, kernbase_offset = 0;

            if ( VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "_KPCR", "KdVersionBlock", &kdvb_offset) )
                goto done;
            if ( VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "_DBGKD_GET_VERSION64", "KernBase", &kernbase_offset) )
                goto done;
            if ( VMI_FAILURE == vmi_read_addr_va(vmi, kpcr+kdvb_offset, 0, &kdvb) )
                goto done;
            if ( VMI_FAILURE == vmi_read_addr_va(vmi, kdvb+kernbase_offset, 0, &windows->ntoskrnl_va) )
                goto done;
            if ( VMI_FAILURE == vmi_translate_kv2p(vmi, windows->ntoskrnl_va, &windows->ntoskrnl) )
                goto done;
        }

        if ( !windows->ntoskrnl )
            goto done;

        dbprint(VMI_DEBUG_MISC, "**KernBase PA=0x%"PRIx64"\n", windows->ntoskrnl);

        /*
         * If the CR3 value points to a pagetable that hasn't been setup yet
         * we need to resort to finding a valid pagetable the old fashioned way.
         */
        if (windows->ntoskrnl_va && !windows->ntoskrnl) {
            windows_find_cr3(vmi);
            if ( VMI_FAILURE == vmi_translate_kv2p(vmi, windows->ntoskrnl_va, &windows->ntoskrnl) )
                goto done;
        }
    }

    // This could happen if we are in file mode or for Win XP
    if (!windows->ntoskrnl) {

        windows->ntoskrnl = get_ntoskrnl_base(vmi, vmi->kpgd);

        // get KdVersionBlock/"_DBGKD_GET_VERSION64"->KernBase
        addr_t kdvb = 0, kernbase_offset = 0;
        if ( VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "KdVersionBlock", NULL, &kdvb) )
            goto done;
        if ( VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "_DBGKD_GET_VERSION64", "KernBase", &kernbase_offset) )
            goto done;

        dbprint(VMI_DEBUG_MISC, "**KdVersionBlock RVA 0x%lx. KernBase RVA: 0x%lx\n", kdvb, kernbase_offset);
        dbprint(VMI_DEBUG_MISC, "**KernBase PA=0x%"PRIx64"\n", windows->ntoskrnl);

        if (windows->ntoskrnl && kdvb && kernbase_offset) {
            if ( VMI_FAILURE == vmi_read_addr_pa(vmi, windows->ntoskrnl + kdvb + kernbase_offset, &windows->ntoskrnl_va) )
                goto done;

            if (!windows->ntoskrnl_va) {
                if ( VMI_FAILURE == vmi_read_32_pa(vmi, windows->ntoskrnl + kdvb + kernbase_offset, (uint32_t*)&windows->ntoskrnl_va) )
                    goto done;
            }

            if (!windows->ntoskrnl_va) {
                dbprint(VMI_DEBUG_MISC, "**failed to find Windows kernel VA via KdVersionBlock\n");
                goto done;
            }
        } else {
            dbprint(VMI_DEBUG_MISC, "**Failed to find required offsets and/or kernel base PA\n");
            goto done;
        }
    }

    dbprint(VMI_DEBUG_MISC, "**KernBase VA=0x%"PRIx64"\n", windows->ntoskrnl_va);

    addr_t ntbuildnumber_rva;
    uint16_t ntbuildnumber = 0;

    // Let's do some sanity checking
    if (VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "NtBuildNumber", NULL, &ntbuildnumber_rva)) {
        goto done;
    }
    if (VMI_FAILURE == vmi_read_16_pa(vmi, windows->ntoskrnl + ntbuildnumber_rva, &ntbuildnumber)) {
        goto done;
    }

    // Let's see if we know the buildnumber
    windows->version = ntbuild2version(ntbuildnumber);

    if (VMI_OS_WINDOWS_UNKNOWN == windows->version) {

        // Let's check the PE header if the buildnumber is unknown
        windows->version = pe2version(vmi, windows->ntoskrnl);

        if (VMI_OS_WINDOWS_NONE == windows->version) {
            dbprint(VMI_DEBUG_MISC, "Failed to find a known version of Windows, "
                    "the Rekall Profile may be incorrect for this VM or the version of Windows is not supported!\n");
            goto done;
        }
    }

    // The system map seems to be good, lets grab all the required offsets
    if (!windows->pdbase_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "_KPROCESS", "DirectoryTableBase", &windows->pdbase_offset)) {
            goto done;
        }
    }
    if (!windows->tasks_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "_EPROCESS", "ActiveProcessLinks", &windows->tasks_offset)) {
            goto done;
        }
    }
    if (!windows->pid_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "_EPROCESS", "UniqueProcessId", &windows->pid_offset)) {
            goto done;
        }
    }
    if (!windows->pname_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "_EPROCESS", "ImageFileName", &windows->pname_offset)) {
            goto done;
        }
    }

    ret = VMI_SUCCESS;
    dbprint(VMI_DEBUG_MISC, "**init from Rekall profile success\n");

done:
    return ret;

}

static status_t
init_from_rekall_profile(vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;
    windows_instance_t windows = vmi->os_data;

    // try to find the kernel if we are not connecting to a file and the kernel pa/va were not already specified.
    if ( vmi->mode != VMI_FILE && ! ( windows->ntoskrnl && windows->ntoskrnl_va ) ) {
        switch ( vmi->page_mode ) {
            case VMI_PM_IA32E: {
                // MSR_SHADOW_GS_BASE - Model Specific Register (MSR) 0xC0000102 which the kernel initialises with the address of the processor’s KPCR.
                // (Intel’s label for this MSR is IA32_KERNEL_GS_BASE.)
                // Actually name seems wrong, since 'shadow' is part of currently loaded GS register that is unreachable for user. It can be and loaded by 'swapgs' instruction.
                // In case we are in user mode, IA32_KERNEL_GS_BASE handles kernel GS_BASE with KPCR
                // CS.L bit has no effect on KPCR and its location
                //
                // So in 64 bit Windows KPCR must be in MSR register 0xC0000101 ("GS shadow" here named GS_BASE)
                // or 0xC0000102 ("IA32_KERNEL_GS_BASE" here named MSR_SHADOW_GS_BASE)

                const reg_t kpcr_registers_to_try[]       = {  GS_BASE,   SHADOW_GS,   MSR_SHADOW_GS_BASE,   FS_BASE  };
#ifdef VMI_DEBUG
                const char *kpcr_registers_to_try_names[] = { "GS_BASE", "SHADOW_GS", "MSR_SHADOW_GS_BASE", "FS_BASE" };
#endif
                dbprint(VMI_DEBUG_MISC, "** (vmi->page_mode == VMI_PM_IA32E) Entering KPCR register selection loop...\n");
                {
                    size_t i = 0;
                    for (i = 0; i < sizeof(kpcr_registers_to_try); ++i) {
                        dbprint(VMI_DEBUG_MISC, "** (vmi->page_mode == VMI_PM_IA32E) => Using kpcr_register_to_use=%s.\n", kpcr_registers_to_try_names[i]);

                        ret = init_from_rekall_profile_real(vmi, kpcr_registers_to_try[i]);
                        if ( VMI_FAILURE != ret )
                            goto done;

                        dbprint(VMI_DEBUG_MISC, "** Trying %s failed.\n", kpcr_registers_to_try_names[i]);
                    }
                }

                dbprint(VMI_DEBUG_MISC, "** KPCR register selection loop ended.\n");
                goto done;
            }

            case VMI_PM_LEGACY: /* Fall-through */
            case VMI_PM_PAE:
                dbprint(VMI_DEBUG_MISC, "** vmi->page_mode in {VMI_PM_LEGACY, VMI_PM_PAE} => Trying FS_BASE.\n");
                ret = init_from_rekall_profile_real(vmi, FS_BASE);
                goto done;

            default:
                dbprint(VMI_DEBUG_MISC, "** vmi->page_mode is unhandled, no KPCR init.\n");
                goto done;
        };
    } else {
        dbprint(VMI_DEBUG_MISC, "** Not retrieving KPCR via 'switch', setting kpcr_register_to_use to unused = 0 .\n");

        reg_t unused = 0;
        ret = init_from_rekall_profile_real(vmi, unused);
        goto done;
    }

done:
    return ret;
}

static status_t
init_core(vmi_instance_t vmi)
{
    windows_instance_t windows = vmi->os_data;
    status_t ret = VMI_FAILURE;

    if (windows->rekall_profile)
        ret = init_from_rekall_profile(vmi);

    /* Fall be here too if the Rekall profile based init fails */
    if ( VMI_FAILURE == ret )
        ret = init_from_kdbg(vmi);

    return ret;
}

status_t
windows_init(vmi_instance_t vmi, GHashTable *config)
{
    status_t status = VMI_FAILURE;
    windows_instance_t windows = NULL;
    os_interface_t os_interface = NULL;
    status_t real_kpgd_found = VMI_FAILURE;

    if (!config) {
        errprint("VMI_ERROR: No config table found\n");
        return VMI_FAILURE;
    }

    if (vmi->os_data != NULL) {
        errprint("VMI_ERROR: os data already initialized, resetting\n");
        bzero(vmi->os_data, sizeof(struct windows_instance));
    } else {
        vmi->os_data = g_malloc0(sizeof(struct windows_instance));
        if ( !vmi->os_data )
            return VMI_FAILURE;
    }

    windows = vmi->os_data;
    windows->version = VMI_OS_WINDOWS_UNKNOWN;

    g_hash_table_foreach(config, (GHFunc)windows_read_config_ghashtable_entries, vmi);

    /* Need to provide this functions so that find_page_mode will work */
    os_interface = g_malloc0(sizeof(struct os_interface));
    if ( !os_interface )
        goto done;

    bzero(os_interface, sizeof(struct os_interface));
    os_interface->os_get_kernel_struct_offset = windows_get_kernel_struct_offset;
    os_interface->os_get_offset = windows_get_offset;
    os_interface->os_pid_to_pgd = windows_pid_to_pgd;
    os_interface->os_pgd_to_pid = windows_pgd_to_pid;
    os_interface->os_ksym2v = windows_kernel_symbol_to_address;
    os_interface->os_usym2rva = windows_export_to_rva;
    os_interface->os_v2sym = windows_rva_to_export;
    os_interface->os_v2ksym = NULL;
    os_interface->os_read_unicode_struct = windows_read_unicode_struct;
    os_interface->os_teardown = windows_teardown;

    vmi->os_interface = os_interface;

    if (VMI_FAILURE == check_pdbase_offset(vmi))
        goto done;

    /* At this point we still don't have a directory table base,
     * so first we try to get it via the driver (fastest way).
     * If the driver gets us a dtb, it will be used _only_ during the init phase,
     * and will be replaced by the real kpgd later. */
    if (VMI_FAILURE == driver_get_vcpureg(vmi, &vmi->kpgd, CR3, 0)) {
        if (VMI_FAILURE == get_kpgd_method2(vmi)) {
            errprint("Could not get kpgd, will not be able to determine page mode\n");
            goto done;
        } else {
            real_kpgd_found = VMI_SUCCESS;
        }
    }

    if (VMI_FAILURE == init_core(vmi))
        goto done;

    if (VMI_PM_UNKNOWN == vmi->page_mode) {
        if (VMI_FAILURE == find_page_mode(vmi)) {
            errprint("Failed to find correct page mode.\n");
            goto done;
        }
    }

    if (VMI_SUCCESS == real_kpgd_found) {
        status = VMI_SUCCESS;
        goto done;
    }

    if ( VMI_SUCCESS == get_kpgd_from_rekall_profile(vmi) ) {
        dbprint(VMI_DEBUG_MISC, "--kpgd from rekall profile success\n");
        status = VMI_SUCCESS;
        goto done;
    }

    /* If we have a dtb via the driver we need to get the real kpgd */
    if (VMI_SUCCESS == get_kpgd_method0(vmi)) {
        dbprint(VMI_DEBUG_MISC, "--kpgd method0 success\n");
        status = VMI_SUCCESS;
        goto done;
    }
    if (VMI_SUCCESS == get_kpgd_method1(vmi)) {
        dbprint(VMI_DEBUG_MISC, "--kpgd method1 success\n");
        status = VMI_SUCCESS;
        goto done;
    }

    if (VMI_SUCCESS == get_kpgd_method2(vmi)) {
        dbprint(VMI_DEBUG_MISC, "--kpgd method2 success\n");
        status = VMI_SUCCESS;
        goto done;
    }

    vmi->kpgd = 0;
    errprint("Failed to find kernel page directory.\n");

done:
    if ( VMI_FAILURE == status )
        windows_teardown(vmi);
    else
        vmi->x86.transition_pages = true;

    return status;
}

status_t windows_teardown(vmi_instance_t vmi)
{

    status_t ret = VMI_SUCCESS;
    windows_instance_t windows = vmi->os_data;

    if (!windows) {
        goto done;
    }

    g_free(windows->rekall_profile);
    g_free(vmi->os_data);
    vmi->os_data = NULL;

done:
    return ret;
}


/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
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
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include <libvmi/x86.h>

#include "driver/driver_wrapper.h"

status_t
windows_kernel_symbol_to_address(
    vmi_instance_t vmi,
    const char *symbol,
    addr_t *kernel_base_address,
    addr_t *address)
{
    status_t ret = VMI_FAILURE;
    addr_t rva = 0;
    windows_instance_t windows = vmi->os_data;

    if (windows == NULL || !windows->ntoskrnl_va) {
        goto exit;
    }

    dbprint(VMI_DEBUG_MISC, "--windows symbol lookup (%s)\n", symbol);

    if (VMI_SUCCESS == json_profile_lookup(vmi, symbol, NULL, &rva)) {
        *address = windows->ntoskrnl_va + rva;
        dbprint(VMI_DEBUG_MISC, "--got symbol from JSON profile (%s --> 0x%.16"PRIx64").\n",
                symbol, *address);
        ret = VMI_SUCCESS;
        goto success;
    }

    if (VMI_SUCCESS == windows_kdbg_lookup(vmi, symbol, address)) {
        dbprint(VMI_DEBUG_MISC, "--got symbol from kdbg (%s --> 0x%"PRIx64").\n", symbol, *address);
        ret = VMI_SUCCESS;
        goto success;
    }

    dbprint(VMI_DEBUG_MISC, "--kdbg lookup failed\n");
    dbprint(VMI_DEBUG_MISC, "--trying kernel PE export table\n");

    /* check exports */
    ACCESS_CONTEXT(ctx,
                   .pm = vmi->page_mode,
                   .translate_mechanism = VMI_TM_PROCESS_PID,
                   .addr = windows->ntoskrnl_va);

    if (VMI_SUCCESS == windows_export_to_rva(vmi, &ctx, symbol, &rva)) {
        *address = windows->ntoskrnl_va + rva;
        dbprint(VMI_DEBUG_MISC, "--got symbol from PE export table (%s --> 0x%.16"PRIx64").\n",
                symbol, *address);
        ret = VMI_SUCCESS;
        goto success;
    }

    dbprint(VMI_DEBUG_MISC, "--kernel PE export table failed\n");

    goto exit;

success:
    if (kernel_base_address) {
        *kernel_base_address = windows->ntoskrnl_va;
    }

exit:
    return ret;
}

/* finds kernel symbol for address, needs vmi_init(..) with VMI_INIT_V2SYM flag */
char*
windows_address_to_kernel_symbol(
    vmi_instance_t vmi,
    addr_t address,
    const access_context_t* UNUSED(ctx))
{
    /* compute relative address */
    windows_instance_t windows = vmi->os_data;
    if (windows == NULL || !windows->ntoskrnl_va) {
        return NULL;
    }
    addr_t rva = address - windows->ntoskrnl_va;

    /* symbol lookup */
    const char* symbol = NULL;
#ifdef ENABLE_JSON_PROFILES
    if (vmi->json.reverse_symbol_table == NULL) {
        dbprint(VMI_DEBUG_MISC, "Address to symbol translation not initialized (set VMI_INIT_V2SYM)\n");
        return NULL;
    }
    symbol = g_hash_table_lookup(vmi->json.reverse_symbol_table, GINT_TO_POINTER(rva));
#else
    dbprint(VMI_DEBUG_MISC, "Need ENABLE_JSON_PROFILES for windows_address_to_kernel_symbol\n");
#endif
    return symbol != NULL ? strdup(symbol) : NULL;
}

/* finds the address of the page global directory for a given pid */
status_t
windows_pid_to_pgd(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t *dtb)
{
    status_t ret = VMI_FAILURE;
    addr_t eprocess = 0;
    int tasks_offset = 0;
    int pdbase_offset = 0;
    windows_instance_t windows = vmi->os_data;

    if (!vmi->os_data)
        return VMI_FAILURE;

    tasks_offset = windows->tasks_offset;
    pdbase_offset = windows->pdbase_offset;

    /* first we need a pointer to this pid's EPROCESS struct */
    eprocess = windows_find_eprocess_list_pid(vmi, pid);
    if (!eprocess) {
        errprint("Could not find EPROCESS struct for pid = %d.\n", pid);
        goto error_exit;
    }

    /* now follow the pointer to the memory descriptor and grab the pgd value */
    ret = vmi_read_addr_va(vmi, eprocess + pdbase_offset - tasks_offset, 0, dtb);

error_exit:
    return ret;
}

status_t
windows_pgd_to_pid(
    vmi_instance_t vmi,
    addr_t pgd,
    vmi_pid_t *pid)
{
    status_t ret = VMI_FAILURE;
    addr_t eprocess = 0;
    int tasks_offset = 0;
    int pid_offset = 0;
    windows_instance_t windows = vmi->os_data;

    if (!vmi->os_data)
        return VMI_FAILURE;

    tasks_offset = windows->tasks_offset;
    pid_offset = windows->pid_offset;

    /* first we need a pointer to this pgd's EPROCESS struct */
    eprocess = windows_find_eprocess_list_pgd(vmi, pgd);
    if (!eprocess) {
        errprint("Could not find EPROCESS struct for pgd = 0x%"PRIx64".\n", pgd);
        goto error_exit;
    }

    /* now follow the pointer to the memory descriptor and grab the pgd value */
    ret = vmi_read_32_va(vmi, eprocess + pid_offset - tasks_offset, 0,
                         (uint32_t*)pid);

error_exit:
    return ret;
}

status_t windows_pte_to_paddr(
    vmi_instance_t vmi,
    page_info_t *info)
{
    windows_instance_t windows = vmi->os_data;

    addr_t pte_value, pte_value_prev;
    vmi->arch_interface.get_pte_values[info->pm](info, &pte_value, &pte_value_prev);

    bool is_inside_proto = PROTOTYPE(pte_value_prev);

    dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: PTE value = 0x%.16"PRIx64", is_inside_proto = %d\n", pte_value, is_inside_proto);

    if (pte_value == 0) {
        dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Zero PTE\n");
        return VMI_FAILURE;
    }

    if (PRESENT(pte_value)) {
        addr_t pfn = (pte_value & windows->pte_info.hard_pfn_mask) >> windows->pte_info.hard_pfn_start_bit;
        info->paddr = (pfn << vmi->page_shift) | (info->vaddr & (vmi->page_size - 1));

        dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Valid PTE pfn = 0x%.16"PRIx64", paddr = 0x%.16"PRIx64"\n", pfn, info->paddr);
        return VMI_SUCCESS;
    }

    if (TRANSITION(pte_value)) {
        addr_t pfn = (pte_value & windows->pte_info.trans_pfn_mask) >> windows->pte_info.trans_pfn_start_bit;
        info->paddr = (pfn << vmi->page_shift) | (info->vaddr & (vmi->page_size - 1));

        dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Transition PTE pfn = 0x%.16"PRIx64", paddr = 0x%.16"PRIx64"\n", pfn, info->paddr);

        if (windows->pte_info.swizzle_mask && !(pte_value & windows->pte_info.swizzle_mask)) {
            info->paddr &= windows->pte_info.trans_invalid_mask;
            dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Transition PTE paddr (unswizzled) = 0x%.16"PRIx64"\n", info->paddr);
        }

        return VMI_SUCCESS;
    }

    if (is_inside_proto) {

        if (PROTOTYPE(pte_value)) {
            dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Subsection PTE\n");
            // content in file
            return VMI_FAILURE;
        }

        dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Pagefile PTE\n");
        // content in pagefile
        return VMI_FAILURE;
    }

    if (PROTOTYPE(pte_value)) {

        addr_t vaddr_proto = (pte_value & windows->pte_info.proto_protoaddr_mask) >> windows->pte_info.proto_protoaddr_start_bit;

        if (vaddr_proto == windows->pte_info.proto_vad_pte) {
            dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Prototype PTE (VAD), vaddr_proto = 0x%.16"PRIx64"\n", vaddr_proto);
            // TODO: implement VAD PTE resolving
            return VMI_FAILURE;
        }

        dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Prototype PTE vaddr = 0x%.16"PRIx64"\n", vaddr_proto);

        if (windows->pte_info.swizzle_mask && !(pte_value & windows->pte_info.swizzle_mask)) {
            vaddr_proto &= windows->pte_info.proto_invalid_mask;
            dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Prototype PTE vaddr (unswizzled) = 0x%.16"PRIx64"\n", vaddr_proto);
        }

        page_info_t p_info = {0};
        vmi->arch_interface.set_pte_values[info->pm](&p_info, 0, pte_value);

        if (VMI_FAILURE == vmi->arch_interface.lookup[info->pm](vmi, info->npt, info->npm, info->pt, vaddr_proto, &p_info)) {
            dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: failed to translate Prototype PTE pointer, vaddr_proto = 0x%.16"PRIx64"\n", vaddr_proto);
            return VMI_FAILURE;
        }

        dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Prototype PTE paddr = 0x%.16"PRIx64"\n", p_info.paddr);

        addr_t value_proto;
        if (VMI_FAILURE == vmi_read_64_pa(vmi, p_info.paddr, &value_proto)) {
            dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: failed to read Prototype PTE value paddr = 0x%.16"PRIx64"\n", p_info.paddr);
            return VMI_FAILURE;
        }

        dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Prototype PTE value = 0x%.16"PRIx64"\n", value_proto);

        vmi->arch_interface.set_pte_values[info->pm](info, value_proto, 0);
        if (VMI_FAILURE == windows_pte_to_paddr(vmi, info)) {
            dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: failed to translate Prototype PTE value = 0x%.16"PRIx64"\n", value_proto);
            return VMI_FAILURE;
        }

        dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Prototype PTE final paddr = 0x%.16"PRIx64"\n", info->paddr);
        return VMI_SUCCESS;
    }

    if (pte_value & windows->pte_info.soft_pagehigh_mask)  {
        dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Pagefile PTE\n");
        // content in pagefile
        return VMI_FAILURE;
    }

    dbprint(VMI_DEBUG_PTERESOLVE, "--PTEResolve: Hardware PTE (VAD)");
    // TODO: implement VAD PTE resolving
    return VMI_FAILURE;
}
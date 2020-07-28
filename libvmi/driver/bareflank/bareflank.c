/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * Author: Tamas K Lengyel <lengyelt@ainfosec.com>
 * Author: Christopher Pelloux <git@chp.io>
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

#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <json-c/json.h>

#include "private.h"
#include "driver/driver_wrapper.h"
#include "driver/memory_cache.h"
#include "driver/bareflank/bareflank.h"
#include "driver/bareflank/bareflank_private.h"

static bool libvmi_to_microv_reg(reg_t reg, mv_uint64_t *mv_reg)
{
    switch (reg) {
        case RAX:
            *mv_reg = mv_reg_t_rax;
            break;
        case RBX:
            *mv_reg = mv_reg_t_rbx;
            break;
        case RCX:
            *mv_reg = mv_reg_t_rcx;
            break;
        case RDX:
            *mv_reg = mv_reg_t_rdx;
            break;
        case RDI:
            *mv_reg = mv_reg_t_rdi;
            break;
        case RSI:
            *mv_reg = mv_reg_t_rsi;
            break;
        case R8:
            *mv_reg = mv_reg_t_r8;
            break;
        case R9:
            *mv_reg = mv_reg_t_r9;
            break;
        case R10:
            *mv_reg = mv_reg_t_r10;
            break;
        case R11:
            *mv_reg = mv_reg_t_r11;
            break;
        case R12:
            *mv_reg = mv_reg_t_r12;
            break;
        case R13:
            *mv_reg = mv_reg_t_r13;
            break;
        case R14:
            *mv_reg = mv_reg_t_r14;
            break;
        case R15:
            *mv_reg = mv_reg_t_r15;
            break;
        case RBP:
            *mv_reg = mv_reg_t_rbp;
            break;
        case RSP:
            *mv_reg = mv_reg_t_rsp;
            break;
        case RIP:
            *mv_reg = mv_reg_t_rip;
            break;
        case CR0:
            *mv_reg = mv_reg_t_cr0;
            break;
        case CR2:
            *mv_reg = mv_reg_t_cr2;
            break;
        case CR3:
            *mv_reg = mv_reg_t_cr3;
            break;
        case CR4:
            *mv_reg = mv_reg_t_cr4;
            break;
        // case CR8: *mv_reg = mv_reg_t_cr8; break;
        case DR0:
            *mv_reg = mv_reg_t_dr0;
            break;
        case DR1:
            *mv_reg = mv_reg_t_dr1;
            break;
        case DR2:
            *mv_reg = mv_reg_t_dr2;
            break;
        case DR3:
            *mv_reg = mv_reg_t_dr3;
            break;
        // case DR4: *mv_reg = mv_reg_t_dr4; break;
        // case DR5: *mv_reg = mv_reg_t_dr5; break;
        case DR6:
            *mv_reg = mv_reg_t_dr6;
            break;
        case DR7:
            *mv_reg = mv_reg_t_dr7;
            break;
        case RFLAGS:
            *mv_reg = mv_reg_t_rflags;
            break;
        case ES_SEL:
            *mv_reg = mv_reg_t_es;
            break;
        case ES_BASE:
            *mv_reg = mv_reg_t_es_base_addr;
            break;
        case ES_LIMIT:
            *mv_reg = mv_reg_t_es_limit;
            break;
        case ES_ARBYTES:
            *mv_reg = mv_reg_t_es_attributes;
            break;
        case CS_SEL:
            *mv_reg = mv_reg_t_cs;
            break;
        case CS_BASE:
            *mv_reg = mv_reg_t_cs_base_addr;
            break;
        case CS_LIMIT:
            *mv_reg = mv_reg_t_cs_limit;
            break;
        case CS_ARBYTES:
            *mv_reg = mv_reg_t_cs_attributes;
            break;
        case SS_SEL:
            *mv_reg = mv_reg_t_ss;
            break;
        case SS_BASE:
            *mv_reg = mv_reg_t_ss_base_addr;
            break;
        case SS_LIMIT:
            *mv_reg = mv_reg_t_ss_limit;
            break;
        case SS_ARBYTES:
            *mv_reg = mv_reg_t_ss_attributes;
            break;
        case DS_SEL:
            *mv_reg = mv_reg_t_ds;
            break;
        case DS_BASE:
            *mv_reg = mv_reg_t_ds_base_addr;
            break;
        case DS_LIMIT:
            *mv_reg = mv_reg_t_ds_limit;
            break;
        case DS_ARBYTES:
            *mv_reg = mv_reg_t_ds_attributes;
            break;
        case FS_SEL:
            *mv_reg = mv_reg_t_fs;
            break;
        case FS_BASE:
            *mv_reg = mv_reg_t_fs_base_addr;
            break;
        case FS_LIMIT:
            *mv_reg = mv_reg_t_fs_limit;
            break;
        case FS_ARBYTES:
            *mv_reg = mv_reg_t_fs_attributes;
            break;
        case GS_SEL:
            *mv_reg = mv_reg_t_gs;
            break;
        case GS_BASE:
            *mv_reg = mv_reg_t_gs_base_addr;
            break;
        case GS_LIMIT:
            *mv_reg = mv_reg_t_gs_limit;
            break;
        case GS_ARBYTES:
            *mv_reg = mv_reg_t_gs_attributes;
            break;
        case LDTR_SEL:
            *mv_reg = mv_reg_t_ldtr;
            break;
        case LDTR_BASE:
            *mv_reg = mv_reg_t_ldtr_base_addr;
            break;
        case LDTR_LIMIT:
            *mv_reg = mv_reg_t_ldtr_limit;
            break;
        case LDTR_ARBYTES:
            *mv_reg = mv_reg_t_ldtr_attributes;
            break;
        case TR_SEL:
            *mv_reg = mv_reg_t_tr;
            break;
        case TR_BASE:
            *mv_reg = mv_reg_t_tr_base_addr;
            break;
        case TR_LIMIT:
            *mv_reg = mv_reg_t_tr_limit;
            break;
        case TR_ARBYTES:
            *mv_reg = mv_reg_t_tr_attributes;
            break;
        // case GDTR: *mv_reg = mv_reg_t_gdtr; break;
        case GDTR_BASE:
            *mv_reg = mv_reg_t_gdtr_base_addr;
            break;
        case GDTR_LIMIT:
            *mv_reg = mv_reg_t_gdtr_limit;
            break;
        // case GDTR: *mv_reg = mv_reg_t_gdtr_attributes; break;
        // case IDTR: *mv_reg = mv_reg_t_idtr; break;
        case IDTR_BASE:
            *mv_reg = mv_reg_t_idtr_base_addr;
            break;
        case IDTR_LIMIT:
            *mv_reg = mv_reg_t_idtr_limit;
            break;
        // case IDTR: *mv_reg = mv_reg_t_idtr_attributes; break;
        default:
            return false;
    }

    return true;
}

static bool libvmi_to_microv_msr(reg_t reg, mv_uint32_t *mv_msr)
{
    switch (reg) {
        case MSR_IA32_SYSENTER_CS:
            *mv_msr = 0x174;
            break;
        case MSR_IA32_SYSENTER_EIP:
            *mv_msr = 0x176;
            break;
        case MSR_IA32_SYSENTER_ESP:
            *mv_msr = 0x175;
            break;
        case MSR_EFER:
            *mv_msr = 0xC0000080;
            break;
        case MSR_STAR:
            *mv_msr = 0xC0000081;
            break;
        case MSR_LSTAR:
            *mv_msr = 0xC0000082;
            break;
        case MSR_CSTAR:
            *mv_msr = 0xC0000083;
            break;
        case MSR_SYSCALL_MASK:
            *mv_msr = 0xC0000084;
            break;
        default:
            return false;
    }

    return true;
}

/*************************************************************/

status_t bareflank_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *reg_val,
    reg_t reg,
    unsigned long vcpu)
{
    mv_status_t ret;
    bareflank_instance_t *bf = bareflank_get_instance(vmi);
    mv_uint64_t mv_reg;
    mv_uint32_t mv_msr;
    mv_uint64_t vpid = MV_VPID_PARENT; // multi-vcpu not yet supported

    if (vcpu != 0) {
        BF_DEBUG("Requested vcpu id %ld not yet supported\n", vcpu);
    }

    if (libvmi_to_microv_reg(reg, &mv_reg)) {
        ret = mv_vp_state_op_reg_val(&bf->handle, vpid, mv_reg, reg_val);
    } else if (libvmi_to_microv_msr(reg, &mv_msr)) {
        ret = mv_vp_state_op_msr_val(&bf->handle, vpid, mv_msr, reg_val);
    } else {
        BF_DEBUG("Register not yet implemented id = %ld\n", reg);
        return VMI_FAILURE;
    }

    if (ret != MV_STATUS_SUCCESS) {
        BF_DEBUG("mv_vp_state_op failed: REG:%ld ret:0x%lx\n", reg, ret);
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

void *
bareflank_get_memory(
    vmi_instance_t vmi,
    addr_t pa,
    uint32_t UNUSED(length))
{
    mv_status_t ret;
    void *space = NULL;
    bareflank_instance_t *bf = bareflank_get_instance(vmi);
    mv_uint64_t ptt_gpa = 0;
    gpa_remap_t map = { .src.gpa = pa };

    if (posix_memalign(&space, 4096, 4096)) {
        BF_DEBUG("posix_memalign failed\n");
        return NULL;
    }

    /* The memory might not be marked present yet in the pagetable
     * so we force a write to it to make sure it's available */
    *(uint64_t*)space = 0xabcdef0123456789;

    // Mark the page as non-pageable
    if (mlock2(space, 4096, MLOCK_ONFAULT) != 0) {
        BF_DEBUG("warning: mlock2 failed\n");
        return NULL;
    }

    ret = mv_vm_state_op_gva_to_gpa(&bf->handle, MV_VMID_SELF, ptt_gpa,
                                    (mv_uint64_t) space, &map.dst.gpa, &map.dst.flags);
    if (ret != MV_STATUS_SUCCESS) {
        BF_DEBUG("mv_vm_state_op_gva_to_gpa failed 0x%lx\n", ret);
        free(space);
        return NULL;
    }
    BF_DEBUG("mv_vm_state_op_gva_to_gpa %p: 0x%lx\n", space, map.dst.gpa);

    assert((map.dst.flags & 0x00000000FFFFFFFF) == 0);
    map.dst.flags |= 1ULL; /* only 1 4k gpa */
    map.src.flags = map.dst.flags;
    map.src.flags |= (MV_GPA_FLAG_READ_ACCESS | MV_GPA_FLAG_WRITE_ACCESS);

    ret = mv_vm_state_op_map_range(&bf->handle, bf->domainid, map.src.gpa,
                                   MV_VMID_SELF, map.dst.gpa, map.dst.flags);
    if (ret != MV_STATUS_SUCCESS) {
        BF_DEBUG("mv_vm_state_op_map_range failed 0x%lx\n", ret);
        free(space);
        return NULL;
    }

    BF_DEBUG("get_memory: remapped %p: 0x%lx -> 0x%lx\n", space, map.dst.gpa, map.src.gpa);

    g_hash_table_insert(bf->remaps,
                        g_memdup(&space, sizeof(void*)),
                        g_memdup(&map, sizeof(gpa_remap_t)));

    return space;
}

void
bareflank_release_memory(
    vmi_instance_t vmi,
    void *memory,
    size_t UNUSED(length))
{
    mv_status_t ret;
    bareflank_instance_t *bf = bareflank_get_instance(vmi);
    gpa_remap_t *map = g_hash_table_lookup(bf->remaps, &memory);

    /* Reverse the EPT remapping */
    if (!map) {
        BF_DEBUG("release_memory: table lookup failed for gva 0x%p\n", memory);
        goto free;
    }

    assert((map->dst.flags & 0x00000000FFFFFFFF) == 1);
    // map->src.flags |= MV_GPA_FLAG_ZOMBIE;

    ret = mv_vm_state_op_unmap_range(&bf->handle, bf->domainid, map->src.gpa,
                                     MV_VMID_SELF, map->dst.gpa, map->dst.flags);
    if (ret != MV_STATUS_SUCCESS) {
        BF_DEBUG("mv_vm_state_op_map_range failed (0x%lx): %p: 0x%lx <- 0x%lx\n", ret, memory, map->src.gpa, map->src.gpa);
    }

    BF_DEBUG("release_memory: restored %p: 0x%lx <- 0x%lx\n", memory, map->src.gpa, map->src.gpa);

#ifdef VMI_DEBUG
    if (*(uint64_t*) memory != 0xabcdef0123456789) {
        BF_DEBUG("release_memory: magic not present 0x%lx !!!\n", *(uint64_t*) memory);
    }
#endif

    g_hash_table_remove(bf->remaps, memory);

free:
    munlock(memory, 4096);
    free(memory);
}

void *
bareflank_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    addr_t paddr = page << vmi->page_shift;

    return memory_cache_insert(vmi, paddr);
}

status_t
bareflank_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t count)
{
    unsigned char *memory = NULL;
    addr_t phys_address = 0;
    addr_t offset = 0;
    size_t buf_offset = 0;

    while (count > 0) {
        size_t write_len = 0;

        /* access the memory */
        phys_address = paddr + buf_offset;
        offset = (vmi->page_size - 1) & phys_address;
        memory = bareflank_read_page(vmi, phys_address >> 12);
        if (NULL == memory) {
            return VMI_FAILURE;
        }

        /* determine how much we can write */
        if ((offset + count) > vmi->page_size) {
            write_len = vmi->page_size - offset;
        } else {
            write_len = count;
        }

        /* do the write */
        memcpy(memory + offset, ((char *) buf) + buf_offset, write_len);

        /* set variables for next loop */
        count -= write_len;
        buf_offset += write_len;
    }

    return VMI_SUCCESS;
}


/*********************************************************************/

void
bareflank_set_id(
    vmi_instance_t vmi,
    uint64_t domainid)
{
    bareflank_get_instance(vmi)->domainid = domainid;
}

void bareflank_set_name(
    vmi_instance_t vmi,
    const char* name)
{
    bareflank_get_instance(vmi)->name = strndup(name, 500);
}

status_t bareflank_get_name_from_domainid(
    vmi_instance_t UNUSED(vmi),
    uint64_t domainid,
    char** name)
{
    /*
     * TODO: The hypervisor needs to actually
     * provide this information.
     */
    if (domainid == 0)
        *name = "dom0";
    else
        *name = "domU";

    return VMI_SUCCESS;
}

uint64_t bareflank_get_domainid_from_name(
    vmi_instance_t UNUSED(vmi),
    const char* name)
{
    /*
     * TODO: The hypervisor needs to actually
     * provide this information.
     */
    if (!strcmp(name, "dom0"))
        return 0;
    else
        return 1;
}

status_t bareflank_get_memsize(
    vmi_instance_t UNUSED(vmi),
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address)
{
    /*
     * TODO: The hypervisor needs to actually
     * provide this information.
     */
    *allocated_ram_size = 0x1000000000;
    *maximum_physical_address = 0x1000000000;
    return VMI_SUCCESS;
}

status_t bareflank_pause_vm(
    vmi_instance_t UNUSED(vmi))
{
    return VMI_SUCCESS;
}

status_t bareflank_resume_vm(
    vmi_instance_t UNUSED(vmi))
{
    return VMI_SUCCESS;
}

status_t
bareflank_test(
    uint64_t UNUSED(domid),
    const char *UNUSED(name),
    uint64_t UNUSED(init_flags),
    void *UNUSED(init_data))
{
    if (!mv_present(MV_SPEC_ID1_VAL)) {
        BF_DEBUG("mv_present failed\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t
bareflank_init(
    vmi_instance_t vmi,
    uint32_t UNUSED(init_flags),
    vmi_init_data_t* UNUSED(init_data))
{
    bareflank_instance_t *bf = g_try_malloc0(sizeof(bareflank_instance_t));

    if ( !bf )
        return VMI_FAILURE;

    if (mv_handle_op_open_handle(MV_SPEC_ID1_VAL, &bf->handle) != MV_STATUS_SUCCESS) {
        BF_DEBUG("mv_handle_op_open failed\n");
        return VMI_FAILURE;
    }

    bf->buffer_space = g_try_malloc0(vmi->page_size);
    if ( !bf->buffer_space ) {
        g_free(bf);
        return VMI_FAILURE;
    }

    vmi->driver.driver_data = (void*)bf;
    vmi->vm_type = NORMAL;

    BF_DEBUG("Bareflank driver init finished\n");

    return VMI_SUCCESS;
}

status_t bareflank_init_vmi(
    vmi_instance_t vmi,
    uint32_t UNUSED(init_flags),
    vmi_init_data_t* UNUSED(init_data))
{
    bareflank_instance_t *bf = bareflank_get_instance(vmi);

    BF_DEBUG("--bareflank: setup live mode\n");
    memory_cache_destroy(vmi);
    memory_cache_init(vmi, bareflank_get_memory, bareflank_release_memory, 0);

    bf->remaps = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);

    return VMI_SUCCESS;
}

void
bareflank_destroy(
    vmi_instance_t vmi)
{
    bareflank_instance_t *bf = bareflank_get_instance(vmi);

    if (!bf) return;

    BF_DEBUG("--bareflank: shutting down driver\n");

    if (mv_handle_op_close_handle(&bf->handle) != MV_STATUS_SUCCESS) {
        BF_DEBUG("mv_handle_op_close failed\n");
    }

    memory_cache_destroy(vmi);

    g_free(bf->buffer_space);
    g_hash_table_destroy(bf->remaps);

    g_free(bf);
    vmi->driver.driver_data = NULL;
}

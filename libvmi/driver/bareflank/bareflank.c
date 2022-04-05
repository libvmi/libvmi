/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * Author: Tamas K Lengyel <lengyelt@ainfosec.com>
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
#include "driver/bareflank/hypercall.h"

static bool get_registers(vmi_instance_t vmi, uint64_t vcpu, json_object **jobj, void *buffer)
{
    uint64_t status;
    size_t size = vmi->page_size;

    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(vcpu,&mask);

    if ( -1 == sched_setaffinity(0, sizeof(mask), &mask) )
        return 0;

    status = hcall_get_registers(buffer, size, bareflank_get_instance(vmi)->domainid);

    CPU_SET(~0ul,&mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    if ( !status )
        *jobj = json_tokener_parse((char *)buffer);

    return !!status;
}

/*************************************************************/

static inline uint64_t parse_reg_value(const char *reg, json_object *root)
{
    // parse the json and get the value of the key
    json_object *return_obj = NULL;
    json_object_object_get_ex(root,reg,&return_obj);
    return json_object_get_int64(return_obj);
}

static inline status_t getkeyfrom_json(json_object *root, reg_t reg, uint64_t *value)
{

    status_t ret = VMI_SUCCESS;
    //TODO: get segment registers
    switch (reg) {
        case CR0:
            *value = parse_reg_value("CR0", root);
            break;
        case CR2:
            *value = parse_reg_value("CR2", root);
            break;
        case CR3:
            *value = parse_reg_value("CR3", root);
            break;
        case CR4:
            *value = parse_reg_value("CR4", root);
            break;
        case RAX:
            *value = parse_reg_value("RAX", root);
            break;
        case RBX:
            *value = parse_reg_value("RBX", root);
            break;
        case RCX:
            *value = parse_reg_value("RCX", root);
            break;
        case RDX:
            *value = parse_reg_value("RDX", root);
            break;
        case RBP:
            *value = parse_reg_value("RBP", root);
            break;
        case RSI:
            *value = parse_reg_value("RSI", root);
            break;
        case RDI:
            *value = parse_reg_value("RDI", root);
            break;
        case RSP:
            *value = parse_reg_value("RSP", root);
            break;
        case R8:
            *value = parse_reg_value("R08", root);
            break;
        case R9:
            *value = parse_reg_value("R09", root);
            break;
        case R10:
            *value = parse_reg_value("R10", root);
            break;
        case R11:
            *value = parse_reg_value("R11", root);
            break;
        case R12:
            *value = parse_reg_value("R12", root);
            break;
        case R13:
            *value = parse_reg_value("R13", root);
            break;
        case R14:
            *value = parse_reg_value("R14", root);
            break;
        case R15:
            *value = parse_reg_value("R15", root);
            break;
        case RIP:
            *value = parse_reg_value("RIP", root);
            break;
        case RFLAGS:
            *value = parse_reg_value("RFL", root);
            break;
        case MSR_EFER:
            *value = parse_reg_value("MSR_EFER", root);
            break;
        default:
            ret = VMI_FAILURE;
            break;
    }
    return ret;
}

status_t bareflank_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
    bareflank_instance_t *bf = bareflank_get_instance(vmi);

    json_object *j_regs = NULL;
    if (get_registers(vmi, vcpu, &j_regs, bf->buffer_space))
        return VMI_FAILURE;

    if ( !j_regs )
        return VMI_FAILURE;

    if (VMI_SUCCESS != getkeyfrom_json(j_regs, reg, value))
        return VMI_FAILURE;

    return VMI_SUCCESS;
}

void *
bareflank_get_memory(
    vmi_instance_t vmi,
    addr_t pa,
    uint32_t UNUSED(prot))
{
    gpointer space = NULL;
    addr_t original_pa = 0;

    if ( posix_memalign(&space, 4096, 4096) )
        return NULL;

    /* The memory might not be marked present yet in the pagetable
     * so we force a write to it to make sure it's available */

    *(uint64_t*)space = 0;

    dbprint(VMI_DEBUG_BAREFLANK, "Allocated remap memory at %p\n", space);

    if ( hcall_v2p((uint64_t)space, &original_pa, bareflank_get_instance(vmi)->domainid) ) {
        dbprint(VMI_DEBUG_BAREFLANK, "Failed to translate %p to physical address\n", space);
        free(space);
        return NULL;
    }

    dbprint(VMI_DEBUG_BAREFLANK, "Remap memory is at %p -> 0x%lx\n", space, original_pa);

    if ( hcall_map_pa((uint64_t)space, pa, bareflank_get_instance(vmi)->domainid) ) {
        dbprint(VMI_DEBUG_BAREFLANK, "Failed to remap at 0x%lx\n", original_pa);
        free(space);
        return NULL;
    }

    dbprint(VMI_DEBUG_BAREFLANK, "Bareflank remapped 0x%lx to 0x%lx\n",
            original_pa, pa);

    g_hash_table_insert(bareflank_get_instance(vmi)->remaps,
                        space,
                        GSIZE_TO_POINTER(original_pa));

    return space;
}

void
bareflank_release_memory(
    vmi_instance_t vmi,
    void *memory,
    size_t UNUSED(length))
{
    bareflank_instance_t *bf = bareflank_get_instance(vmi);
    addr_t pa = GPOINTER_TO_SIZE(g_hash_table_lookup(bf->remaps, memory));

    /* Reverse the EPT remapping */
    if ( pa ) {
        dbprint(VMI_DEBUG_BAREFLANK, "Bareflank release & remap %p -> 0x%lx\n", memory, pa);

        if ( hcall_map_pa((uint64_t)memory, pa, bareflank_get_instance(vmi)->domainid) )
            dbprint(VMI_DEBUG_BAREFLANK, "Bareflank remap failed\n");

        g_hash_table_remove(bf->remaps, memory);
    }

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

status_t bareflank_test(uint64_t UNUSED(domid), const char* UNUSED(name))
{
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;

    rax = bareflank_cpuid(&rbx, &rcx, &rdx, NULL);

    dbprint(VMI_DEBUG_BAREFLANK, "Running Bareflank CPUID signature: %i %i %i %i\n",
            (int)rax, (int)rbx, (int)rcx, (int)rdx);

    if ( (int)rax != 42 || (int)rbx != 42 || (int)rcx != 42 || (int)rdx != 42 )
        return VMI_FAILURE;

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

    bf->buffer_space = g_try_malloc0(vmi->page_size);
    if ( !bf->buffer_space ) {
        g_free(bf);
        return VMI_FAILURE;
    }

    vmi->driver.driver_data = (void*)bf;
    vmi->vm_type = NORMAL;

    dbprint(VMI_DEBUG_BAREFLANK, "Bareflank driver init finished\n");

    return VMI_SUCCESS;
}

status_t bareflank_init_vmi(
    vmi_instance_t vmi,
    uint32_t UNUSED(init_flags),
    vmi_init_data_t* UNUSED(init_data))
{
    bareflank_instance_t *bf = bareflank_get_instance(vmi);

    dbprint(VMI_DEBUG_BAREFLANK, "--bareflank: setup live mode\n");
    memory_cache_destroy(vmi);
    memory_cache_init(vmi, bareflank_get_memory, bareflank_release_memory, 0);

    bf->remaps = g_hash_table_new(g_direct_hash, g_direct_equal);

    return VMI_SUCCESS;
}

void
bareflank_destroy(
    vmi_instance_t vmi)
{
    bareflank_instance_t *bf = bareflank_get_instance(vmi);

    if (!bf) return;

    dbprint(VMI_DEBUG_BAREFLANK, "--bareflank: shutting down driver\n");

    memory_cache_destroy(vmi);

    g_free(bf->buffer_space);
    g_hash_table_destroy(bf->remaps);

    g_free(bf);
    vmi->driver.driver_data = NULL;
}

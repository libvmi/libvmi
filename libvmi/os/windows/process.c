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

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "private.h"

char *
windows_get_eprocess_name(
    vmi_instance_t vmi,
    addr_t paddr)
{
    size_t name_length = 16;   //TODO verify that this is correct for all versions
    windows_instance_t windows = vmi->os_data;

    if (windows == NULL) {
        return NULL;
    }

    addr_t name_paddr = paddr + windows->pname_offset;
    char *name = (char *) g_malloc0(name_length);

    if ( !name )
        return NULL;

    if ( VMI_FAILURE == vmi_read_pa(vmi, name_paddr, name_length, name, NULL)) {
        return name;
    } else {
        free(name);
        return NULL;
    }
}

#define MAGIC1 0x1b0003
#define MAGIC2 0x200003
#define MAGIC3 0x300003
#define MAGIC4 0x580003
#define MAGIC5 0x260003
static inline int
check_magic_2k(
    uint32_t a)
{
    return (a == MAGIC1);
}

static inline int
check_magic_vista(
    uint32_t a)
{
    return (a == MAGIC2 || a == MAGIC3);
}

static inline int
check_magic_7(
    uint32_t a)
{
    return (a == MAGIC4 || a == MAGIC5);
}

static inline int
check_magic_unknown(
    uint32_t a)
{
    return (a == MAGIC1 || a == MAGIC2 || a == MAGIC3 || a == MAGIC4 || a == MAGIC5);
}

static check_magic_func
get_check_magic_func(
    vmi_instance_t vmi)
{
    check_magic_func rtn = NULL;
    if (vmi->os_data == NULL) {
        return &check_magic_unknown;
    }

    switch (((windows_instance_t)vmi->os_data)->version) {
        case VMI_OS_WINDOWS_2000:
        case VMI_OS_WINDOWS_XP:
        case VMI_OS_WINDOWS_2003:
            rtn = &check_magic_2k;
            break;
        case VMI_OS_WINDOWS_VISTA:
            rtn = &check_magic_vista;
            break;
        case VMI_OS_WINDOWS_7:
            rtn = &check_magic_7;
            break;
        case VMI_OS_WINDOWS_2008:
        case VMI_OS_WINDOWS_UNKNOWN:
            rtn = &check_magic_unknown;
            break;
        default:
            rtn = &check_magic_unknown;
            dbprint
            (VMI_DEBUG_MISC, "--%s: illegal value in vmi->os.windows_instance.version\n",
             __FUNCTION__);
            break;
    }

    return rtn;
}

int
find_pname_offset(
    vmi_instance_t vmi,
    check_magic_func check)
{
    addr_t block_pa = 0;
    addr_t offset = 0;
    uint32_t value = 0;
    void *bm = 0;

    bm = boyer_moore_init((unsigned char *)"Idle", 4);

#define BLOCK_SIZE 1024 * 1024 * 1
    unsigned char block_buffer[BLOCK_SIZE];

    if (NULL == check) {
        check = get_check_magic_func(vmi);
    }

    for (block_pa = 4096; block_pa + BLOCK_SIZE < vmi->max_physical_address; block_pa += BLOCK_SIZE) {
        if ( VMI_FAILURE == vmi_read_pa(vmi, block_pa, BLOCK_SIZE, block_buffer, NULL) ) {
            continue;
        }

        for (offset = 0; offset < BLOCK_SIZE; offset += 8) {
            memcpy(&value, block_buffer + offset, 4);

            if (check(value)) { // look for specific magic #
                dbprint
                (VMI_DEBUG_MISC, "--%s: found magic value 0x%.8"PRIx32" @ offset 0x%.8"PRIx64"\n",
                 __FUNCTION__, value, block_pa + offset);

                unsigned char haystack[0x500];

                if ( VMI_FAILURE == vmi_read_pa(vmi, block_pa + offset, 0x500, haystack, NULL) ) {
                    continue;
                }

                int i = boyer_moore2(bm, haystack, 0x500);

                if (-1 == i) {
                    continue;
                } else {
                    vmi->init_task = block_pa + offset;
                    dbprint
                    (VMI_DEBUG_MISC, "--%s: found Idle process at 0x%.8"PRIx64" + 0x%x\n",
                     __FUNCTION__, block_pa + offset, i);
                    boyer_moore_fini(bm);
                    return i;
                }
            }
        }
    }
    boyer_moore_fini(bm);
    return 0;
}

static addr_t
find_process_by_name(
    vmi_instance_t vmi,
    check_magic_func check,
    addr_t start_address,
    const char *name)
{

    dbprint(VMI_DEBUG_MISC, "--searching for process by name: %s\n", name);

    addr_t block_pa = 0;
    addr_t offset = 0;
    uint32_t value = 0;

    unsigned char block_buffer[VMI_PS_4KB];

    if (NULL == check) {
        check = get_check_magic_func(vmi);
    }

    for (block_pa = start_address; block_pa + VMI_PS_4KB < vmi->max_physical_address;
            block_pa += VMI_PS_4KB) {
        if ( VMI_FAILURE == vmi_read_pa(vmi, block_pa, VMI_PS_4KB, block_buffer, NULL) )
            continue;

        for (offset = 0; offset < VMI_PS_4KB; offset += 8) {
            memcpy(&value, block_buffer + offset, 4);

            if (check(value)) { // look for specific magic #

                char *procname = windows_get_eprocess_name(vmi, block_pa + offset);
                if (procname) {
                    if (strncmp(procname, name, 50) == 0) {
                        free(procname);
                        return block_pa + offset;
                    }
                    free(procname);
                }
            }
        }
    }
    return 0;
}

addr_t
windows_find_eprocess(
    vmi_instance_t vmi,
    const char *name)
{

    addr_t start_address = 0;
    windows_instance_t windows = vmi->os_data;
    check_magic_func check = get_check_magic_func(vmi);

    if (windows == NULL) {
        return 0;
    }

    if (!windows->pname_offset) {
        if (windows->rekall_profile) {
            if ( VMI_FAILURE == rekall_profile_symbol_to_rva(windows->rekall_profile, "_EPROCESS", "ImageFileName", &windows->pname_offset) )
                return 0;
        } else {
            windows->pname_offset = find_pname_offset(vmi, check);
        }

        if (!windows->pname_offset) {
            dbprint(VMI_DEBUG_MISC, "--failed to find pname_offset\n");
            return 0;
        } else {
            dbprint(VMI_DEBUG_MISC, "**set os.windows_instance.pname_offset (0x%"PRIx64")\n",
                    windows->pname_offset);
        }
    }

    if (vmi->init_task) {
        start_address = vmi->init_task;
    }

    return find_process_by_name(vmi, check, start_address, name);
}

addr_t
eprocess_list_search(
    vmi_instance_t vmi,
    addr_t list_head,
    int offset,
    size_t len,
    void *value)
{
    addr_t next_process = 0;
    addr_t tasks_offset = 0;
    addr_t rtnval = 0;
    void *buf = g_malloc0(len);

    if ( !buf )
        goto exit;

    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks_offset) )
        goto exit;

    if ( VMI_FAILURE == vmi_read_addr_va(vmi, list_head + tasks_offset, 0, &next_process) )
        goto exit;

    if ( VMI_FAILURE == vmi_read_va(vmi, list_head + offset, 0, len, buf, NULL) )
        goto exit;

    if (memcmp(buf, value, len) == 0) {
        rtnval = list_head + tasks_offset;
        goto exit;
    }
    list_head = next_process;

    while (1) {
        addr_t tmp_next = 0;

        if ( VMI_FAILURE == vmi_read_addr_va(vmi, next_process, 0, &tmp_next) )
            goto exit;

        if (list_head == tmp_next) {
            break;
        }

        if ( VMI_FAILURE == vmi_read_va(vmi, next_process + offset - tasks_offset, 0, len, buf, NULL) )
            goto exit;

        if (memcmp(buf, value, len) == 0) {
            rtnval = next_process;
            goto exit;
        }
        next_process = tmp_next;
    }

exit:
    g_free(buf);
    return rtnval;
}

addr_t
windows_find_eprocess_list_pid(
    vmi_instance_t vmi,
    vmi_pid_t pid)
{
    size_t len = sizeof(vmi_pid_t);
    int pid_offset = 0;
    addr_t list_head = 0;

    if ( !vmi->os_data )
        return 0;

    if ( VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &list_head) )
        return 0;

    pid_offset = ((windows_instance_t)vmi->os_data)->pid_offset;

    return eprocess_list_search(vmi, list_head, pid_offset, len, &pid);
}

addr_t
windows_find_eprocess_list_pgd(
    vmi_instance_t vmi,
    addr_t pgd)
{
    int pdbase_offset = 0;
    size_t len = 0;
    addr_t list_head = 0;

    if ( !vmi->os_data )
        return 0;

    if ( VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &list_head) )
        return 0;

    pdbase_offset = ((windows_instance_t)vmi->os_data)->pdbase_offset;

    if (vmi->page_mode == VMI_PM_LEGACY || vmi->page_mode == VMI_PM_PAE)
        len = sizeof(uint32_t);
    else
        len = sizeof(addr_t);

    return eprocess_list_search(vmi, list_head, pdbase_offset, len, &pgd);
}


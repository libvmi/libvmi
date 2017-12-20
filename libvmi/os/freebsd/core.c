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
#include "config/config_parser.h"
#include "driver/driver_wrapper.h"
#include "os/freebsd/freebsd.h"

void freebsd_read_config_ghashtable_entries(char* key, gpointer value,
        vmi_instance_t vmi);

static status_t init_from_rekall_profile(vmi_instance_t vmi)
{

    status_t ret = VMI_FAILURE;
    freebsd_instance_t freebsd_instance = vmi->os_data;

    if (!freebsd_instance->pmap_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(freebsd_instance->rekall_profile, "vmspace", "vm_pmap", &freebsd_instance->pmap_offset)) {
            goto done;
        }
    }
    if (!freebsd_instance->vmspace_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(freebsd_instance->rekall_profile, "proc", "p_vmspace", &freebsd_instance->vmspace_offset)) {
            goto done;
        }
    }
    if (!freebsd_instance->pid_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(freebsd_instance->rekall_profile, "proc", "p_pid", &freebsd_instance->pid_offset)) {
            goto done;
        }
    }
    if (!freebsd_instance->name_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(freebsd_instance->rekall_profile, "proc", "p_comm", &freebsd_instance->name_offset)) {
            goto done;
        }
    }
    if (!freebsd_instance->pgd_offset) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(freebsd_instance->rekall_profile, "pmap", "pm_cr3", &freebsd_instance->pgd_offset)) {
            goto done;
        }
    }
    if (!vmi->init_task) {
        if (VMI_FAILURE == rekall_profile_symbol_to_rva(freebsd_instance->rekall_profile, "allproc", NULL, &vmi->init_task)) {
            goto done;
        }
    }

    ret = VMI_SUCCESS;

done:
    return ret;
}

status_t freebsd_init(vmi_instance_t vmi, GHashTable *config)
{

    status_t rc;
    os_interface_t os_interface = NULL;

    if (!config) {
        errprint("No config table found\n");
        return VMI_FAILURE;
    }

    if (vmi->os_data != NULL) {
        errprint("os data already initialized, reinitializing\n");
        free(vmi->os_data);
    }

    vmi->os_data = g_malloc0(sizeof(struct freebsd_instance));
    if ( !vmi->os_data )
        return VMI_FAILURE;

    freebsd_instance_t freebsd_instance = vmi->os_data;

    g_hash_table_foreach(config, (GHFunc)freebsd_read_config_ghashtable_entries,
                         vmi);

    if (freebsd_instance->rekall_profile)
        rc = init_from_rekall_profile(vmi);
    else
        rc = freebsd_symbol_to_address(vmi, "allproc", NULL, &vmi->init_task);

    if (VMI_FAILURE == rc) {
        errprint("Could not get initproc from Rekall profile or System.map\n");
        goto _exit;
    }

    vmi->init_task = canonical_addr(vmi->init_task);

#if defined(I386) || defined(X86_64)
    rc = driver_get_vcpureg(vmi, &vmi->kpgd, CR3, 0);
#endif

    if (VMI_FAILURE == rc) {
        dbprint(VMI_DEBUG_MISC, "**Here is where freebsd_filemode_init would be called\n");
        goto _exit;
    }

    dbprint(VMI_DEBUG_MISC, "**set vmi->kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    os_interface = g_malloc(sizeof(struct os_interface));
    if ( !os_interface )
        goto _exit;

    bzero(os_interface, sizeof(struct os_interface));
    os_interface->os_get_offset = freebsd_get_offset;
    os_interface->os_pid_to_pgd = freebsd_pid_to_pgd;
    os_interface->os_pgd_to_pid = freebsd_pgd_to_pid;
    os_interface->os_ksym2v = freebsd_symbol_to_address;
    os_interface->os_usym2rva = NULL;
    os_interface->os_v2sym = freebsd_system_map_address_to_symbol;
    os_interface->os_read_unicode_struct = NULL;
    os_interface->os_teardown = freebsd_teardown;

    vmi->os_interface = os_interface;

    return VMI_SUCCESS;

_exit:
    g_free(vmi->os_data);
    vmi->os_data = NULL;
    return VMI_FAILURE;
}

void freebsd_read_config_ghashtable_entries(char* key, gpointer value,
        vmi_instance_t vmi)
{

    freebsd_instance_t freebsd_instance = vmi->os_data;

    if (key == NULL || value == NULL) {
        errprint("VMI_ERROR: key or value point to NULL\n");
        return;
    }

    if (strncmp(key, "sysmap", CONFIG_STR_LENGTH) == 0) {
        freebsd_instance->sysmap = strdup((char *)value);
        goto _done;
    }

    if (strncmp(key, "rekall_profile", CONFIG_STR_LENGTH) == 0) {
        freebsd_instance->rekall_profile = strdup((char *)value);
        goto _done;
    }

    if (strncmp(key, "freebsd_pmap", CONFIG_STR_LENGTH) == 0) {
        freebsd_instance->pmap_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "freebsd_vmspace", CONFIG_STR_LENGTH) == 0) {
        freebsd_instance->vmspace_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "freebsd_pid", CONFIG_STR_LENGTH) == 0) {
        freebsd_instance->pid_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "freebsd_name", CONFIG_STR_LENGTH) == 0) {
        freebsd_instance->name_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "freebsd_pgd", CONFIG_STR_LENGTH) == 0) {
        freebsd_instance->pgd_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "ostype", CONFIG_STR_LENGTH) == 0 || strncmp(key, "os_type", CONFIG_STR_LENGTH) == 0) {
        goto _done;
    }

    if (strncmp(key, "name", CONFIG_STR_LENGTH) == 0) {
        goto _done;
    }

    if (strncmp(key, "domid", CONFIG_STR_LENGTH) == 0) {
        goto _done;
    }

    if (strncmp(key, "physoffset", CONFIG_STR_LENGTH) == 0) {
        goto _done;
    }

    warnprint("Invalid offset %s given for FreeBSD target\n", key);

_done:
    return;
}

status_t freebsd_get_offset(vmi_instance_t vmi, const char* offset_name, addr_t *offset)
{
    const size_t max_length = 100;
    freebsd_instance_t freebsd_instance = vmi->os_data;

    if (freebsd_instance == NULL) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        return 0;
    }

    if (offset_name == NULL || offset == NULL) {
        errprint("VMI_ERROR: offset_name or offset point to NULL\n");
        return 0;
    }

    if (strncmp(offset_name, "freebsd_pmap", max_length) == 0) {
        *offset = freebsd_instance->pmap_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "freebsd_vmspace", max_length) == 0) {
        *offset = freebsd_instance->vmspace_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "freebsd_pid", max_length) == 0) {
        *offset = freebsd_instance->pid_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "freebsd_name", max_length) == 0) {
        *offset = freebsd_instance->name_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "freebsd_pgd", max_length) == 0) {
        *offset = freebsd_instance->pgd_offset;
        return VMI_SUCCESS;
    }

    warnprint("Invalid offset name in freebsd_get_offset (%s).\n", offset_name);
    return VMI_FAILURE;
}

status_t freebsd_teardown(vmi_instance_t vmi)
{
    freebsd_instance_t freebsd_instance = vmi->os_data;

    if (vmi->os_data == NULL) {
        return VMI_SUCCESS;
    }

    free(freebsd_instance->sysmap);
    free(freebsd_instance->rekall_profile);
    free(vmi->os_data);

    vmi->os_data = NULL;
    return VMI_SUCCESS;
}

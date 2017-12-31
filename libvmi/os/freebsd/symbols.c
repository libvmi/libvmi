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
#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "os/freebsd/freebsd.h"

#define MAX_ROW_LENGTH 500

static int
get_symbol_row(
    FILE * f,
    char *row,
    const char *symbol,
    int position)
{
    int ret = VMI_FAILURE;

    while (fgets(row, MAX_ROW_LENGTH, f) != NULL) {
        char *token = NULL;

        /* find the correct token to check */
        int curpos = 0;
        int position_copy = position;

        while (position_copy > 0 && curpos < MAX_ROW_LENGTH) {
            if (isspace(row[curpos])) {
                while (isspace(row[curpos])) {
                    row[curpos] = '\0';
                    ++curpos;
                }
                --position_copy;
                continue;
            }
            ++curpos;
        }
        if (position_copy == 0) {
            token = row + curpos;
            while (curpos < MAX_ROW_LENGTH) {
                if (isspace(row[curpos])) {
                    row[curpos] = '\0';
                }
                ++curpos;
            }
        } else {  /* something went wrong in the loop above */
            goto error_exit;
        }

        /* check the token */
        if (strncmp(token, symbol, MAX_ROW_LENGTH) == 0) {
            ret = VMI_SUCCESS;
            break;
        }
    }

error_exit:
    if (ret == VMI_FAILURE) {
        memset(row, 0, MAX_ROW_LENGTH);
    }
    return ret;
}

static status_t
freebsd_system_map_symbol_to_address(
    vmi_instance_t vmi,
    const char *symbol,
    addr_t *address)
{
    FILE *f = NULL;
    char *row = NULL;
    status_t ret = VMI_FAILURE;

    freebsd_instance_t freebsd_instance = vmi->os_data;

    if (freebsd_instance == NULL) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        goto done;
    }

    if ((NULL == freebsd_instance->sysmap) || (strlen(freebsd_instance->sysmap) == 0)) {
        errprint("VMI_WARNING: No freebsd sysmap configured\n");
        goto done;
    }

    row = safe_malloc(MAX_ROW_LENGTH);
    if ((f = fopen(freebsd_instance->sysmap, "r")) == NULL) {
        fprintf(stderr,
                "ERROR: could not find System.map file after checking:\n");
        fprintf(stderr, "\t%s\n", freebsd_instance->sysmap);
        fprintf(stderr,
                "To fix this problem, add the correct sysmap entry to /etc/libvmi.conf\n");
        (*address) = 0;
        goto done;
    }
    if (get_symbol_row(f, row, symbol, 2) == VMI_FAILURE) {
        (*address) = 0;
        goto done;
    }

    (*address) = (addr_t) strtoull(row, NULL, 16);

    ret = VMI_SUCCESS;

done:
    if (row)
        free(row);
    if (f)
        fclose(f);
    return ret;
}

char* freebsd_system_map_address_to_symbol(
    vmi_instance_t vmi,
    addr_t address,
    const access_context_t *ctx)
{
    FILE *f = NULL;
    char *row = NULL;
    char* address_str = NULL;
    char* it = NULL;
    char* symbol = NULL;
    int size = 0;
    freebsd_instance_t freebsd_instance = vmi->os_data;

    switch (ctx->translate_mechanism) {
        case VMI_TM_PROCESS_PID:
            if (ctx->pid != 0)
                goto err;
            break;
        case VMI_TM_PROCESS_DTB:
            if (ctx->dtb != vmi->kpgd)
                goto err;
            break;
        default:
            goto err;
    };

    if (freebsd_instance == NULL) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        goto done;
    }

    if ((NULL == freebsd_instance->sysmap) || (strlen(freebsd_instance->sysmap) == 0)) {
        errprint("VMI_WARNING: No freebsd sysmap configured\n");
        goto done;
    }

    row = safe_malloc(MAX_ROW_LENGTH);
    if ((f = fopen(freebsd_instance->sysmap, "r")) == NULL) {
        fprintf(stderr,
                "ERROR: could not find System.map file after checking:\n");
        fprintf(stderr, "\t%s\n", freebsd_instance->sysmap);
        fprintf(stderr,
                "To fix this problem, add the correct sysmap entry to /etc/libvmi.conf\n");
        goto done;
    }
    size = snprintf(NULL,0,"%"PRIx64"", address) + 1;
    address_str = g_malloc0(size);
    snprintf(address_str, size, "%"PRIx64"", address);
    if (get_symbol_row(f, row, address_str, 0) == VMI_FAILURE) {
        goto done;
    }

    // skip two columns
    for (it=row; *it!=0; it++);
    for (it++; *it!=0; it++);
    it++;

    symbol = strdup(it);

done:
    if (row)
        free(row);
    if (f)
        fclose(f);
    if (address_str)
        free(address_str);
    return symbol;

err:
    errprint("VMI_WARNING: Lookup is implemented for kernel symbols only\n");
    return NULL;
}

status_t
freebsd_symbol_to_address(
    vmi_instance_t vmi,
    const char *symbol,
    addr_t* UNUSED(__unused),
    addr_t* address)
{
    status_t ret = VMI_FAILURE;
    freebsd_instance_t freebsd_instance = vmi->os_data;

    if (freebsd_instance == NULL) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        goto done;
    }

    if (!freebsd_instance->sysmap && !freebsd_instance->rekall_profile) {
        errprint("VMI_WARNING: No freebsd sysmap and Rekall profile configured\n");
        goto done;
    }

    if (freebsd_instance->sysmap)
        ret = freebsd_system_map_symbol_to_address(vmi, symbol, address);
    else
        ret = rekall_profile_symbol_to_rva(freebsd_instance->rekall_profile,
                                           symbol, NULL, address);

done:
    return ret;
}

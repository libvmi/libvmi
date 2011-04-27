/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
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

#include "private.h"
#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <string.h>

status_t linux_system_map_symbol_to_address (
        vmi_instance_t vmi, char *symbol, uint32_t *address)
{
    FILE *f = NULL;
    char *row = NULL;
    int ret = VMI_SUCCESS;

    if ((NULL == vmi->sysmap) || (strlen(vmi->sysmap) == 0)){
        vmi->sysmap = strndup("unknown", 10);
    }

    row = safe_malloc(MAX_ROW_LENGTH);
    if ((f = fopen(vmi->sysmap, "r")) == NULL){
        fprintf(stderr, "ERROR: could not find System.map file after checking:\n");
        fprintf(stderr, "\t%s\n", vmi->sysmap);
        fprintf(stderr, "To fix this problem, add the correct sysmap entry to /etc/libvmi.conf\n");
        ret = VMI_FAILURE;
        goto error_exit;
    }
    if (get_symbol_row(f, row, symbol, 2) == VMI_FAILURE){
        ret = VMI_FAILURE;
        goto error_exit;
    }

    *address = (uint32_t) strtoul(row, NULL, 16);

error_exit:
    if (row) free(row);
    if (f) fclose(f);
    return ret;
}

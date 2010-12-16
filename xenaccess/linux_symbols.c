/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2007  Bryan D. Payne (bryan@thepaynes.cc)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * --------------------
 * This file contains utility functions reading information from the
 * System.map file which contains symbol information from the linux
 * kernel created by nm.
 *
 * File: linux_system_map.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 *
 * $Id: linux_symbols.c 190 2009-01-25 20:41:07Z hajime.inoue $
 * $Date: 2006-12-06 01:23:30 -0500 (Wed, 06 Dec 2006) $
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "xa_private.h"

int linux_system_map_symbol_to_address (
        xa_instance_t *instance, char *symbol, uint32_t *address)
{
    FILE *f = NULL;
    char *row = NULL;
    int ret = XA_SUCCESS;

    if ((NULL == instance->sysmap) || (strlen(instance->sysmap) == 0)){
#ifdef ENABLE_XEN
        instance->sysmap =
            linux_predict_sysmap_name(instance->m.xen.domain_id);
#endif /* ENABLE_XEN */
    }

    if ((row = malloc(MAX_ROW_LENGTH)) == NULL ){
        ret = XA_FAILURE;
        goto error_exit;
    }
    if ((f = fopen(instance->sysmap, "r")) == NULL){
        fprintf(stderr, "ERROR: could not find System.map file after checking:\n");
        fprintf(stderr, "\t%s\n", instance->sysmap);
        fprintf(stderr, "To fix this problem, add the correct sysmap entry to /etc/xenaccess.conf\n");
        ret = XA_FAILURE;
        goto error_exit;
    }
    if (get_symbol_row(f, row, symbol, 2) == XA_FAILURE){
        ret = XA_FAILURE;
        goto error_exit;
    }

    *address = (uint32_t) strtoul(row, NULL, 16);

error_exit:
    if (row) free(row);
    if (f) fclose(f);
    return ret;
}

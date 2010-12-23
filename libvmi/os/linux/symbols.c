/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "private.h"

int linux_system_map_symbol_to_address (
        vmi_instance_t instance, char *symbol, uint32_t *address)
{
    FILE *f = NULL;
    char *row = NULL;
    int ret = VMI_SUCCESS;

    if ((NULL == instance->sysmap) || (strlen(instance->sysmap) == 0)){
#ifdef ENABLE_XEN
        instance->sysmap =
            linux_predict_sysmap_name(instance->m.xen.domain_id);
#endif /* ENABLE_XEN */
    }

    row = safe_malloc(MAX_ROW_LENGTH);
    if ((f = fopen(instance->sysmap, "r")) == NULL){
        fprintf(stderr, "ERROR: could not find System.map file after checking:\n");
        fprintf(stderr, "\t%s\n", instance->sysmap);
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

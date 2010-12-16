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
 * Core windows functionality, primarily iniitalization routines for now.
 *
 * File: windows_core.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 */

#include "xenaccess.h"
#include "xa_private.h"

/* Tries to find the kernel page directory by doing an exhaustive search
 * through the memory space for the System process.  The page directory
 * location is then pulled from this eprocess struct.
 */
int get_kpgd_method2 (xa_instance_t *instance, uint32_t *sysproc)
{
    int ret = XA_SUCCESS;

    /* get address for Idle process */
    if ((*sysproc = windows_find_eprocess(instance, "System")) == 0){
        xa_dbprint("WARNING: failed to find System process.\n");
        ret = xa_report_error(instance, 0, XA_EMINOR);
        if (XA_FAILURE == ret) goto error_exit;
    }
    xa_dbprint("--got PA to PsInititalSystemProcess (0x%.8x).\n", *sysproc);

    /* get address for page directory (from system process) */
    /*TODO this 0x18 offset should not be hard coded below */
    if (xa_read_long_phys(
            instance, *sysproc + 0x18, &(instance->kpgd)) == XA_FAILURE){
        xa_dbprint("WARNING: failed to resolve PD for Idle process\n");
        ret = xa_report_error(instance, 0, XA_EMINOR);
        if (XA_FAILURE == ret) goto error_exit;
    }
    instance->kpgd += instance->page_offset; /* store vaddr */

    if (instance->kpgd == instance->page_offset){
        ret = xa_report_error(instance, 0, XA_EMINOR);
    }

error_exit:
    return ret;
}

/* Tries to find the kernel page directory using the RVA value for
 * PSInitialSystemProcess and the ntoskrnl value to lookup the System
 * process, and the extract the page directory location from this
 * eprocess struct.
 */
int get_kpgd_method1 (xa_instance_t *instance, uint32_t *sysproc)
{
    int ret = XA_SUCCESS;

    if (xa_read_long_sym(
            instance, "PsInitialSystemProcess", sysproc) == XA_FAILURE){
        xa_dbprint("WARNING: failed to read pointer for system process\n");
        ret = xa_report_error(instance, 0, XA_EMINOR);
        if (XA_FAILURE == ret) goto error_exit;
    }
    *sysproc = xa_translate_kv2p(instance, *sysproc);
    xa_dbprint("--got PA to PsInititalSystemProcess (0x%.8x).\n", *sysproc);

    if (xa_read_long_phys(
            instance,
            *sysproc + instance->os.windows_instance.pdbase_offset,
            &(instance->kpgd)) == XA_FAILURE){
        xa_dbprint("WARNING: failed to resolve pointer for system process\n");
        ret = xa_report_error(instance, 0, XA_EMINOR);
        if (XA_FAILURE == ret) goto error_exit;
    }
    instance->kpgd += instance->page_offset; /* store vaddr */

    if (instance->kpgd == instance->page_offset){
        ret = xa_report_error(instance, 0, XA_EMINOR);
    }

error_exit:
    return ret;
}

int windows_init (xa_instance_t *instance)
{
    int ret = XA_SUCCESS;
    uint32_t sysproc = 0;

    // get base address for kernel image in memory unless
    // it has already been set in the configuration file.
    if(instance->os.windows_instance.ntoskrnl == 0){
        instance->os.windows_instance.ntoskrnl = get_ntoskrnl_base(instance);
        if (!instance->os.windows_instance.ntoskrnl){
            ret = xa_report_error(instance, 0, XA_EMINOR);
            if (XA_FAILURE == ret) goto error_exit;
        }
        xa_dbprint("--got ntoskrnl (0x%.8x).\n", instance->os.windows_instance.ntoskrnl);
    }

    /* get the kernel page directory location */
    if (get_kpgd_method1(instance, &sysproc) == XA_FAILURE){
        xa_dbprint("--kpgd method1 failed, trying method2\n");
        if (get_kpgd_method2(instance, &sysproc) == XA_FAILURE){
            fprintf(stderr, "ERROR: failed to find kernel page directory.\n");
            ret = xa_report_error(instance, 0, XA_EMINOR);
            if (XA_FAILURE == ret) goto error_exit;
        }
    }
    xa_dbprint("**set instance->kpgd (0x%.8x).\n", instance->kpgd);
//    printf("kpgd search --> 0x%.8x\n", xa_find_kernel_pd(instance));

    /* get address start of process list */
    xa_read_long_phys(
        instance,
        sysproc + instance->os.windows_instance.tasks_offset,
        &(instance->init_task));
    xa_dbprint("**set instance->init_task (0x%.8x).\n", instance->init_task);

    /*TODO add some checking to test for PAE mode like in linux_core */

error_exit:
    return ret;
}

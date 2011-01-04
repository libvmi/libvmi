/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include "libvmi.h"
#include "private.h"

/* Tries to find the kernel page directory by doing an exhaustive search
 * through the memory space for the System process.  The page directory
 * location is then pulled from this eprocess struct.
 */
status_t get_kpgd_method2 (vmi_instance_t vmi, uint32_t *sysproc)
{
    int ret = VMI_SUCCESS;

    /* get address for Idle process */
    if ((*sysproc = windows_find_eprocess(vmi, "System")) == 0){
        dbprint("WARNING: failed to find System process.\n");
        ret = vmi_report_error(vmi, 0, VMI_EMINOR);
        if (VMI_FAILURE == ret) goto error_exit;
    }
    dbprint("--got PA to PsInititalSystemProcess (0x%.8x).\n", *sysproc);

    /* get address for page directory (from system process) */
    /*TODO this 0x18 offset should not be hard coded below */
    if (vmi_read_long_phys(
            vmi, *sysproc + 0x18, &(vmi->kpgd)) == VMI_FAILURE){
        dbprint("WARNING: failed to resolve PD for Idle process\n");
        ret = vmi_report_error(vmi, 0, VMI_EMINOR);
        if (VMI_FAILURE == ret) goto error_exit;
    }
    vmi->kpgd += vmi->page_offset; /* store vaddr */

    if (vmi->kpgd == vmi->page_offset){
        ret = vmi_report_error(vmi, 0, VMI_EMINOR);
    }

error_exit:
    return ret;
}

/* Tries to find the kernel page directory using the RVA value for
 * PSInitialSystemProcess and the ntoskrnl value to lookup the System
 * process, and the extract the page directory location from this
 * eprocess struct.
 */
status_t get_kpgd_method1 (vmi_instance_t vmi, uint32_t *sysproc)
{
    int ret = VMI_SUCCESS;

    if (vmi_read_long_sym(
            vmi, "PsInitialSystemProcess", sysproc) == VMI_FAILURE){
        dbprint("WARNING: failed to read pointer for system process\n");
        ret = vmi_report_error(vmi, 0, VMI_EMINOR);
        if (VMI_FAILURE == ret) goto error_exit;
    }
    *sysproc = vmi_translate_kv2p(vmi, *sysproc);
    dbprint("--got PA to PsInititalSystemProcess (0x%.8x).\n", *sysproc);

    if (vmi_read_long_phys(
            vmi,
            *sysproc + vmi->os.windows_instance.pdbase_offset,
            &(vmi->kpgd)) == VMI_FAILURE){
        dbprint("WARNING: failed to resolve pointer for system process\n");
        ret = vmi_report_error(vmi, 0, VMI_EMINOR);
        if (VMI_FAILURE == ret) goto error_exit;
    }
    vmi->kpgd += vmi->page_offset; /* store vaddr */

    if (vmi->kpgd == vmi->page_offset){
        ret = vmi_report_error(vmi, 0, VMI_EMINOR);
    }

error_exit:
    return ret;
}

status_t windows_init (vmi_instance_t vmi)
{
    int ret = VMI_SUCCESS;
    uint32_t sysproc = 0;

    // get base address for kernel image in memory unless
    // it has already been set in the configuration file.
    if(vmi->os.windows_instance.ntoskrnl == 0){
        vmi->os.windows_instance.ntoskrnl = get_ntoskrnl_base(vmi);
        if (!vmi->os.windows_instance.ntoskrnl){
            ret = vmi_report_error(vmi, 0, VMI_EMINOR);
            if (VMI_FAILURE == ret) goto error_exit;
        }
        dbprint("--got ntoskrnl (0x%.8x).\n", vmi->os.windows_instance.ntoskrnl);
    }

    /* get the kernel page directory location */
    if (get_kpgd_method1(vmi, &sysproc) == VMI_FAILURE){
        dbprint("--kpgd method1 failed, trying method2\n");
        if (get_kpgd_method2(vmi, &sysproc) == VMI_FAILURE){
            errprint("Failed to find kernel page directory.\n");
            ret = vmi_report_error(vmi, 0, VMI_EMINOR);
            if (VMI_FAILURE == ret) goto error_exit;
        }
    }
    dbprint("**set kpgd (0x%.8x).\n", vmi->kpgd);

    /* get address start of process list */
    vmi_read_long_phys(
        vmi,
        sysproc + vmi->os.windows_instance.tasks_offset,
        &(vmi->init_task));
    dbprint("**set init_task (0x%.8x).\n", vmi->init_task);

    /*TODO add some checking to test for PAE mode like in linux_core */

error_exit:
    return ret;
}

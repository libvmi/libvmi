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
#include "driver/interface.h"

status_t linux_init (vmi_instance_t vmi)
{
    int ret = VMI_FAILURE;
    unsigned char *memory = NULL;
    uint32_t local_offset = 0;

    if (linux_system_map_symbol_to_address(
             vmi, "swapper_pg_dir", &vmi->kpgd) == VMI_FAILURE){
        errprint("Failed to lookup 'swapper_pg_dir' address.\n");
        goto error_exit;
    }
    dbprint("--got vaddr for swapper_pg_dir (0x%.8x).\n", vmi->kpgd);

    if (driver_is_pv(vmi)){
        vmi->kpgd -= vmi->page_offset;
        if (vmi_read_32_pa(
                vmi, vmi->kpgd, &(vmi->kpgd)) == VMI_FAILURE){
            errprint("Failed to get physical addr for kpgd.\n");
            goto error_exit;
        }
    }
    dbprint("**set vmi->kpgd (0x%.8x).\n", vmi->kpgd);

    memory = vmi_access_kernel_sym(vmi, "init_task", &local_offset, PROT_READ);
    if (NULL == memory){
        dbprint("--address lookup failure, switching PAE mode\n");
        vmi->pae = !vmi->pae;
        dbprint("**set pae = %d\n", vmi->pae);
        memory = vmi_access_kernel_sym(vmi, "init_task", &local_offset, PROT_READ);
        if (NULL == memory){
            errprint("Failed to get task list head 'init_task'.\n");
            goto error_exit;
        }
    }
    vmi->init_task =
        *((uint32_t*)(memory + local_offset +
        vmi->os.linux_instance.tasks_offset));
    dbprint("**set init_task (0x%.8x).\n", vmi->init_task);
    munmap(memory, vmi->page_size);

    ret = VMI_SUCCESS;
error_exit:
    return ret;
}

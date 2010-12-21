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

int linux_init (vmi_instance_t instance)
{
    int ret = VMI_SUCCESS;
    unsigned char *memory = NULL;
    uint32_t local_offset = 0;

    if (linux_system_map_symbol_to_address(
             instance, "swapper_pg_dir", &instance->kpgd) == VMI_FAILURE){
        fprintf(stderr, "ERROR: failed to lookup 'swapper_pg_dir' address\n");
        ret = vmi_report_error(instance, 0, VMI_EMINOR);
        if (VMI_FAILURE == ret) goto error_exit;
    }
    dbprint("--got vaddr for swapper_pg_dir (0x%.8x).\n", instance->kpgd);

    if (!instance->hvm){
        instance->kpgd -= instance->page_offset;
        if (vmi_read_long_phys(
                instance, instance->kpgd, &(instance->kpgd)) == VMI_FAILURE){
            fprintf(stderr, "ERROR: failed to get physical addr for kpgd\n");
            ret = vmi_report_error(instance, 0, VMI_EMINOR);
            if (VMI_FAILURE == ret) goto error_exit;
        }
    }
    dbprint("**set instance->kpgd (0x%.8x).\n", instance->kpgd);
//    printf("kpgd search --> 0x%.8x\n", vmi_find_kernel_pd(instance));

    memory = vmi_access_kernel_sym(instance, "init_task", &local_offset, PROT_READ);
    if (NULL == memory){
        dbprint("--address lookup failure, switching PAE mode\n");
        instance->pae = !instance->pae;
        dbprint("**set instance->pae = %d\n", instance->pae);
        memory = vmi_access_kernel_sym(instance, "init_task", &local_offset, PROT_READ);
        if (NULL == memory){
            fprintf(stderr, "ERROR: failed to get task list head 'init_task'\n");
            ret = vmi_report_error(instance, 0, VMI_EMINOR);
            //TODO should we switch PAE mode back?
            if (VMI_FAILURE == ret) goto error_exit;
        }
    }
    instance->init_task =
        *((uint32_t*)(memory + local_offset +
        instance->os.linux_instance.tasks_offset));
    dbprint("**set instance->init_task (0x%.8x).\n", instance->init_task);
    munmap(memory, instance->page_size);

error_exit:
    return ret;
}

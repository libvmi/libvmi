/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "private.h"


/* finds the task struct for a given pid */
unsigned char *linux_get_taskstruct (
        vmi_instance_t vmi, int pid, uint32_t *offset)
{
    unsigned char *memory = NULL;
    uint32_t list_head = 0, next_process = 0;
    int task_pid = 0;
    int pid_offset = vmi->os.linux_instance.pid_offset;
    int tasks_offset = vmi->os.linux_instance.tasks_offset;

    /* first we need a pointer to this pid's task_struct */
    next_process = vmi->init_task;
    list_head = next_process;

    while (1){
        memory = vmi_access_kernel_va(vmi, next_process, offset, PROT_READ);
        if (NULL == memory){
            errprint("Failed to get task list next pointer.\n");
            goto error_exit;
        }
        memcpy(&next_process, memory + *offset, 4);

        /* if we are back at the list head, we are done */
        if (list_head == next_process){
            goto error_exit;
        }

        memcpy(&task_pid,
               memory + *offset + pid_offset - tasks_offset,
               4
        );
        
        /* if pid matches, then we found what we want */
        if (task_pid == pid){
            return memory;
        }
        munmap(memory, vmi->page_size);
    }

error_exit:
    if (memory) munmap(memory, vmi->page_size);
    return NULL;
}

/* finds the address of the page global directory for a given pid */
uint32_t linux_pid_to_pgd (vmi_instance_t vmi, int pid)
{
    unsigned char *memory = NULL;
    uint32_t pgd = 0, ptr = 0, offset = 0;
    int mm_offset = vmi->os.linux_instance.mm_offset;
    int tasks_offset = vmi->os.linux_instance.tasks_offset;
    int pgd_offset = vmi->os.linux_instance.pgd_offset;

    /* first we need a pointer to this pid's task_struct */
    memory = linux_get_taskstruct(vmi, pid, &offset);
    if (NULL == memory){
        errprint("Could not find task struct for pid = %d.\n", pid);
        goto error_exit;
    }

    /* now follow the pointer to the memory descriptor and
       grab the pgd value */
    memcpy(&ptr, memory + offset + mm_offset - tasks_offset, 4);
    munmap(memory, vmi->page_size);
    vmi_read_32_va(vmi, ptr + pgd_offset, 0, &pgd);

    /* convert pgd into a machine address */
    pgd = vmi_translate_kv2p(vmi, pgd);

    /* update the cache with this new pid->pgd mapping */
    vmi_update_pid_cache(vmi, pid, pgd);

error_exit:
    return pgd;
}

void *linux_access_kernel_symbol (
        vmi_instance_t vmi, char *symbol, uint32_t *offset, int prot)
{
    uint32_t virt_address;
    uint32_t address;

    /* check the LRU cache */
    if (vmi_check_cache_sym(vmi, symbol, 0, &address)){
        return vmi_access_ma(vmi, address, offset, PROT_READ);
    }

    /* get the virtual address of the symbol */
    if (linux_system_map_symbol_to_address(
            vmi, symbol, &virt_address) == VMI_FAILURE){
        return NULL;
    }

    vmi_update_cache(vmi, symbol, virt_address, 0, 0);
    return vmi_access_kernel_va(vmi, virt_address, offset, prot);
}

/* fills the taskaddr struct for a given linux process */
status_t vmi_linux_get_taskaddr (
        vmi_instance_t vmi, int pid, vmi_linux_taskaddr_t *taskaddr)
{
    unsigned char *memory;
    uint32_t ptr = 0, offset = 0;
    int mm_offset = vmi->os.linux_instance.mm_offset;
    int tasks_offset = vmi->os.linux_instance.tasks_offset;
    int addr_offset = vmi->os.linux_instance.addr_offset;

    /* find the right task struct */
    memory = linux_get_taskstruct(vmi, pid, &offset);
    if (NULL == memory){
        errprint("Could not find task struct for pid = %d.\n", pid);
        goto error_exit;
    }

    /* copy the information out of the memory descriptor */
    memcpy(&ptr, memory + offset + mm_offset - tasks_offset, 4);
    munmap(memory, vmi->page_size);
    memory = vmi_access_kernel_va(vmi, ptr, &offset, PROT_READ);
    if (NULL == memory){
        errprint("Failed to follow mm pointer (0x%x).\n", ptr);
        goto error_exit;
    }
    memcpy(
        taskaddr,
        memory + offset + addr_offset,
        sizeof(vmi_linux_taskaddr_t)
    );
    munmap(memory, vmi->page_size);

    return VMI_SUCCESS;

error_exit:
    if (memory) munmap(memory, vmi->page_size);
    return VMI_FAILURE;
}

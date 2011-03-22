/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include <libvmi/libvmi.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>

void linux_printaddr (vmi_linux_taskaddr_t taskaddr)
{
    printf("start_code = 0x%.8lx\n", taskaddr.start_code);
    printf("end_code = 0x%.8lx\n", taskaddr.end_code);
    printf("start_data = 0x%.8lx\n", taskaddr.start_data);
    printf("end_data = 0x%.8lx\n", taskaddr.end_data);
    printf("start_brk = 0x%.8lx\n", taskaddr.start_brk);
    printf("brk = 0x%.8lx\n", taskaddr.brk);
    printf("start_stack = 0x%.8lx\n", taskaddr.start_stack);
    printf("arg_stack = 0x%.8lx\n", taskaddr.arg_stack);
    printf("arg_end = 0x%.8lx\n", taskaddr.arg_end);
    printf("env_start = 0x%.8lx\n", taskaddr.env_start);
    printf("env_end = 0x%.8lx\n", taskaddr.env_end);
}

void windows_printaddr (vmi_windows_peb_t peb)
{
    printf("ImageBaseAddress = 0x%.8x\n", peb.ImageBaseAddress);
    printf("ProcessHeap = 0x%.8x\n", peb.ProcessHeap);
}

#define PAGE_SIZE 1 << 12

int main (int argc, char **argv)
{
    vmi_instance_t vmi;
    vmi_linux_taskaddr_t taskaddr;
    vmi_windows_peb_t peb;
    char *memory = NULL;
    uint32_t offset = 0;

    /* this is the VM or file that we are looking at */
    char *name = argv[1];

    /* This is the pid that we are looking at, passed as
       an argument on the command line. */
    int pid = atoi(argv[2]);

    /* initialize the libvmi library */
    if (vmi_init_name(&vmi, VMI_MODE_AUTO, name) == VMI_FAILURE){
        perror("failed to init LibVMI library");
        goto error_exit;
    }

    /* get the relavent addresses for this process */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)){
        if (vmi_linux_get_taskaddr(vmi, pid, &taskaddr) == VMI_FAILURE){
            perror("failed to get task addresses");
            goto error_exit;
        }
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)){
        if (vmi_windows_get_peb(vmi, pid, &peb) == VMI_FAILURE){
            perror("failed to get process addresses from peb");
            goto error_exit;
        }
    }

    /* print out the process address information */
    printf("Memory descriptor addresses for pid = %d:\n", pid);
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)){
        linux_printaddr(taskaddr);
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)){
        windows_printaddr(peb);
    }

    /* grab the memory at the start of the code segment
       for this process and print it out */
    memory = (char *) malloc(PAGE_SIZE);
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)){
        vmi_read_va(vmi, taskaddr.start_code, pid, memory, PAGE_SIZE);
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)){
        vmi_read_va(vmi, peb.ImageBaseAddress, pid, memory, PAGE_SIZE);
    }
    vmi_print_hex(memory, PAGE_SIZE);
    printf("offset = 0x%x\n", offset);
    free(memory);

error_exit:
    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    return 0;
}

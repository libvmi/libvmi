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

#define PAGE_SIZE 1 << 12

int main (int argc, char **argv)
{
    vmi_instance_t vmi;
    char *memory = (char *) malloc(PAGE_SIZE);

    /* this is the VM or file that we are looking at */
    char *name = argv[1];

    /* this is the address to map */
    char *addr_str = argv[2];
    uint32_t addr = (uint32_t) strtoul(addr_str, NULL, 16);

    /* initialize the libvmi library */
    if (vmi_init(&vmi, VMI_MODE_AUTO, name) == VMI_FAILURE){
        perror("failed to init LibVMI library");
        goto error_exit;
    }

    /* get the symbol's memory page */
    if (PAGE_SIZE != vmi_read_va(vmi, addr, 0, memory, PAGE_SIZE)){
        perror("failed to map memory");
        goto error_exit;
    }
    vmi_print_hex(memory, PAGE_SIZE);

error_exit:
    if (memory) free(memory);

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    return 0;
}

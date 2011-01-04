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
    unsigned char *memory = NULL;
    uint32_t offset;

    /* this is the domain ID that we are looking at */
    uint32_t dom = atoi(argv[1]);

    /* this is the symbol to map */
    char *symbol = argv[2];

    /* initialize the libvmi library */
    if (vmi_init_vm_id_strict(dom, vmi) == VMI_FAILURE){
        perror("failed to init LibVMI library");
        goto error_exit;
    }

    /* get the symbol's memory page */
    memory = vmi_access_kernel_sym(vmi, symbol, &offset, PROT_READ);
    if (NULL == memory){
        perror("failed to get symbol's memory");
        goto error_exit;
    }
    printf("offset = 0x%.8x\n", offset);
    vmi_print_hex(memory, PAGE_SIZE);

error_exit:

    /* sanity check to unmap shared pages */
    if (memory) munmap(memory, PAGE_SIZE);

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    return 0;
}

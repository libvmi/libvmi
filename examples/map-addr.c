/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <libvmi/libvmi.h>
#include <libvmi/private.h>

#ifdef ENABLE_XEN
int main (int argc, char **argv)
{
    xa_instance_t xai;
    unsigned char *memory = NULL;
    uint32_t offset;

    /* this is the domain ID that we are looking at */
    uint32_t dom = atoi(argv[1]);

    /* this is the address to map */
    char *addr_str = argv[2];
    uint32_t addr = (uint32_t) strtoul(addr_str, NULL, 16);

    /* initialize the xen access library */
    if (xa_init_vm_id_strict(dom, &xai) == XA_FAILURE){
        perror("failed to init XenAccess library");
        goto error_exit;
    }

    /* get the symbol's memory page */
    memory = xa_access_kernel_va(&xai, addr, &offset, PROT_READ);
//    memory = xa_access_pa(&xai, addr, &offset, PROT_READ);
//    memory = xa_access_ma(&xai, addr, &offset, PROT_READ);
    if (NULL == memory){
        perror("failed to map memory");
        goto error_exit;
    }
    printf("offset = 0x%.8x\n", offset);
    print_hex(memory, xai.page_size);

error_exit:

    /* sanity check to unmap shared pages */
    if (memory) munmap(memory, xai.page_size);

    /* cleanup any memory associated with the XenAccess instance */
    xa_destroy(&xai);

    return 0;
}

#else

int main (int argc, char **argv)
{
    printf("The map addr example is intended to work with a live Xen domain, but\n");
    printf("XenAccess was compiled without support for Xen.  Exiting...\n");
}

#endif /* ENABLE_XEN */


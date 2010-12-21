/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <libvmi/libvmi.h>

#ifdef ENABLE_XEN
int main (int argc, char **argv)
{
    xa_instance_t xai;
    char *filename = NULL;
    FILE *f = NULL;
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    uint32_t address = 0;

    /* this is the domain ID that we are looking at */
    uint32_t dom = atoi(argv[1]);

    /* this is the file name to write the memory image to */
    filename = strndup(argv[2], 50);

    /* initialize the xen access library */
    if (xa_init_vm_id_lax(dom, &xai) == XA_FAILURE){
        perror("failed to init XenAccess library");
        goto error_exit;
    }

    /* open the file for writing */
    if ((f = fopen(filename, "w+")) == NULL){
        perror("failed to open file for writing");
        goto error_exit;
    }

    /* assuming that we are looking at xen domain, and not image file */
    while (address < xai.m.xen.size){

        /* access the memory */
        memory = xa_access_pa(&xai, address, &offset, PROT_READ);

        /* write memory to file */
        if (memory){
            /* memory mapped, just write to file */
            size_t written = fwrite(memory, 1, xai.page_size, f);
            if (written != xai.page_size){
                perror("failed to write memory to file");
                goto error_exit;
            }
            munmap(memory, xai.page_size);
        }
        else{
            /* memory not mapped, write zeros to maintain offset */
            unsigned char *zeros = malloc(xai.page_size);
            memset(zeros, 0, xai.page_size);
            size_t written = fwrite(zeros, 1, xai.page_size, f);
            if (written != xai.page_size){
                perror("failed to write zeros to file");
                goto error_exit;
            }
            free(zeros);
        }

        /* move on to the next page */
        address += xai.page_size;
    }

error_exit:
    if (memory){ munmap(memory, xai.page_size); }
    if (f){ fclose(f); }

    /* cleanup any memory associated with the XenAccess instance */
    xa_destroy(&xai);

    return 0;
}

#else

int main (int argc, char **argv)
{
    printf("The dump memory example is intended to work with a live Xen domain, but\n");
    printf("XenAccess was compiled without support for Xen.  Exiting...\n");
}

#endif /* ENABLE_XEN */

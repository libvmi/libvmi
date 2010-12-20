/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include "private.h"

void print_hex (unsigned char *data, int length)
{
    int i, j, numrows, index;

    numrows = (length+15)>>4;
    
    for (i = 0; i < numrows; ++i){
        /* print the byte count */
        printf("%.8x|  ", i*16);

        /* print the first 8 hex values */
        for (j = 0; j < 8; ++j){
            index = i*16+j;
            if (index < length){
                printf("%.2x ", data[index]);
            }
            else{
                printf("   ");
            }
        }
        printf(" ");

        /* print the second 8 hex values */
        for ( ; j < 16; ++j){
            index = i*16+j;
            if (index < length){
                printf("%.2x ", data[index]);
            }
            else{
                printf("   ");
            }
        }
        printf("  ");

        /* print the ascii values */
        for (j = 0; j < 16; ++j){
            index = i*16+j;
            if (index < length){
                if (isprint((int)data[index])){
                    printf("%c", data[index]);
                }
                else{
                    printf(".");
                }
            }
        }
        printf("\n");
    }
}

#ifdef ENABLE_XEN
void print_dominfo (xc_dominfo_t info)
{
    printf("xc_dominfo_t struct for dom%d\n", info.domid);
    printf("\tdomid = %d\n", info.domid);
    printf("\tssidref = %d\n", info.ssidref);
    printf("\tdying = %d\n", info.dying);
    printf("\tcrashed = %d\n", info.crashed);
    printf("\tshutdown = %d\n", info.shutdown);
    printf("\tpaused = %d\n", info.paused);
    printf("\tblocked = %d\n", info.blocked);
    printf("\trunning = %d\n", info.running);
    printf("\tshutdown_reason = %d\n", info.shutdown_reason);
    printf("\tnr_pages = %lu\n", info.nr_pages);
    printf("\tshared_info_frame = %lu\n", info.shared_info_frame);
    /* printf("\tcpu_time = %x\n", info.cpu_time); */
    printf("\tmax_memkb = %lu\n", info.max_memkb);
    printf("\tnr_online_vcpus = %d\n", info.nr_online_vcpus);
    printf("\tmax_vcpu_id = %d\n", info.max_vcpu_id);
    printf("\n");
}
#endif /* ENABLE_XEN */

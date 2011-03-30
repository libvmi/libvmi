/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include "libvmi.h"

void vmi_print_hex (unsigned char *data, unsigned long length)
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


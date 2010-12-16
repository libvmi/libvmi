/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2007  Bryan D. Payne (bryan@thepaynes.cc)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * --------------------
 * This file contains utility functions for printing out data and
 * debugging information.
 *
 * File: xa_pretty_print.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 *
 * $Id: xa_pretty_print.c 155 2008-12-15 18:40:15Z bdpayne $
 * $Date: 2006-11-29 20:38:20 -0500 (Wed, 29 Nov 2006) $
 */

#include "xa_private.h"

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

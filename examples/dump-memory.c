/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libvmi/libvmi.h>
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>

#define PAGE_SIZE 1 << 12

int main (int argc, char **argv)
{
    vmi_instance_t vmi;
    char *filename = NULL;
    FILE *f = NULL;
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    addr_t address = 0;

    /* this is the VM or file that we are looking at */
    char *name = argv[1];

    /* this is the file name to write the memory image to */
    filename = strndup(argv[2], 50);

    /* initialize the libvmi library */
    if (vmi_init(&vmi, VMI_MODE_AUTO, name) == VMI_FAILURE){
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }

    /* open the file for writing */
    if ((f = fopen(filename, "w+")) == NULL){
        printf("failed to open file for writing.\n");
        goto error_exit;
    }

    while (address < vmi_get_memsize(vmi)){

        /* write memory to file */
        if (PAGE_SIZE == vmi_read_pa(vmi, address, memory, PAGE_SIZE)){
            /* memory mapped, just write to file */
            size_t written = fwrite(memory, 1, PAGE_SIZE, f);
            if (written != PAGE_SIZE){
                printf("failed to write memory to file.\n");
                goto error_exit;
            }
            munmap(memory, PAGE_SIZE);
        }
        else{
            /* memory not mapped, write zeros to maintain offset */
            unsigned char *zeros = malloc(PAGE_SIZE);
            memset(zeros, 0, PAGE_SIZE);
            size_t written = fwrite(zeros, 1, PAGE_SIZE, f);
            if (written != PAGE_SIZE){
                printf("failed to write zeros to file.\n");
                goto error_exit;
            }
            free(zeros);
        }

        /* move on to the next page */
        address += PAGE_SIZE;
    }

error_exit:
    if (memory) free(memory);
    if (f) fclose(f);

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    return 0;
}

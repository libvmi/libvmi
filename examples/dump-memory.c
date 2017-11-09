/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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

#include <config.h>
#include <libvmi/libvmi.h>
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>

#define PAGE_SIZE 1 << 12

int
main(
    int argc,
    char **argv)
{
    if ( argc != 3 )
        return 1;

    vmi_instance_t vmi = NULL;
    char *filename = NULL;
    FILE *f = NULL;
    unsigned char memory[PAGE_SIZE];
    unsigned char zeros[PAGE_SIZE];

    memset(zeros, 0, PAGE_SIZE);
    addr_t address = 0;
    addr_t size = 0;
    vmi_mode_t mode;

    /* this is the VM or file that we are looking at */
    char *name = argv[1];

    /* this is the file name to write the memory image to */
    filename = strndup(argv[2], 50);

    if (VMI_FAILURE == vmi_get_access_mode(vmi, (void*)name, VMI_INIT_DOMAINNAME, NULL, &mode) )
        goto error_exit;

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, (void*)name, VMI_INIT_DOMAINNAME, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }

    /* open the file for writing */
    if ((f = fopen(filename, "w+")) == NULL) {
        printf("failed to open file for writing.\n");
        goto error_exit;
    }

    size = vmi_get_max_physical_address(vmi);

    while (address < size) {

        /* write memory to file */
        if (VMI_SUCCESS == vmi_read_pa(vmi, address, PAGE_SIZE, memory, NULL)) {
            /* memory mapped, just write to file */
            size_t written = fwrite(memory, 1, PAGE_SIZE, f);

            if (written != PAGE_SIZE) {
                printf("failed to write memory to file.\n");
                goto error_exit;
            }
        } else {
            /* memory not mapped, write zeros to maintain offset */
            size_t written = fwrite(zeros, 1, PAGE_SIZE, f);

            if (written != PAGE_SIZE) {
                printf("failed to write zeros to file.\n");
                goto error_exit;
            }
        }

        /* move on to the next page */
        address += PAGE_SIZE;
    }

error_exit:
    if (f)
        fclose(f);

    free(filename);

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    return 0;
}

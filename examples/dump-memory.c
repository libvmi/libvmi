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
    if ( argc < 3 ) {
        fprintf(stderr, "Usage: %s <name of VM> <dump file> [<socket>]\n", argv[0]);
        return 1;
    }

    vmi_instance_t vmi = NULL;
    char *filename = NULL;
    FILE *f = NULL;
    unsigned char memory[PAGE_SIZE];
    unsigned char zeros[PAGE_SIZE];
    int retcode = 1;

    memset(zeros, 0, PAGE_SIZE);
    addr_t address = 0;
    addr_t size = 0;
    vmi_mode_t mode;
    memory_map_t *memmap = NULL;
    vmi_init_data_t *init_data = NULL;

    /* this is the VM or file that we are looking at */
    char *name = argv[1];

    /* this is the file name to write the memory image to */
    filename = strndup(argv[2], 50);

    if (argc == 4) {
        char *path = argv[3];

        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    if (VMI_FAILURE == vmi_get_access_mode(vmi, (void*)name, VMI_INIT_DOMAINNAME, init_data, &mode) )
        goto error_exit;

    /*
     * For bareflank we have to pass-in the actual memory map of the machine.
     */
    if ( mode == VMI_BAREFLANK ) {
        printf("Using this example on Bareflank is not safe.\n");
        printf("You have to adjust it to match your machine before running it.\n");
        goto error_exit;

        /* The following is an example based on the e820 map described in
         * notes/memory_map.txt. */
        uint32_t e820_entries = 5;

        memmap = malloc(sizeof(memory_map_t) + sizeof(addr_t) * 2 * e820_entries);
        memmap->count = e820_entries;
        memmap->range[0][0] = 0xfff;
        memmap->range[0][1] = 0x57fff;
        memmap->range[1][0] = 0x60000;
        memmap->range[1][1] = 0x97fff;
        memmap->range[2][0] = 0x100000;
        memmap->range[2][1] = 0xdbfb8fff;
        memmap->range[3][0] = 0xdcfff000;
        memmap->range[3][1] = 0xdcffffff;
        memmap->range[4][0] = 0x100000000;
        memmap->range[4][1] = 0x21e5fffff;

        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_MEMMAP;
        init_data->entry[0].data = memmap;
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, (void*)name, VMI_INIT_DOMAINNAME, init_data, NULL)) {
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

    retcode = 0;
error_exit:
    if (f)
        fclose(f);
    if (memmap)
        free(memmap);
    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    free(filename);

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    return retcode;
}

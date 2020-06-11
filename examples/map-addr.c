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

#include <libvmi/libvmi.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>

#define PAGE_SIZE 1 << 12

int
main(
    int argc,
    char **argv)
{
    if ( argc < 3 ) {
        fprintf(stderr, "Usage: %s <name of VM> <virtual address> [<socket>]\n", argv[0]);
        return 1;
    }

    vmi_instance_t vmi = {0};
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;
    unsigned char *memory = malloc(PAGE_SIZE);

    /* this is the VM or file that we are looking at */
    char *name = argv[1];

    /* this is the address to map */
    char *addr_str = argv[2];
    addr_t addr = (addr_t) strtoul(addr_str, NULL, 16);

    /* kvmi socket ? */
    if (argc == 4) {
        char *path = argv[3];

        init_data = malloc(sizeof(vmi_init_data_t)+ sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME, init_data,
                              VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }

    /* get the symbol's memory page */
    if (VMI_FAILURE == vmi_read_va(vmi, addr, 0, PAGE_SIZE, memory, NULL)) {
        printf("failed to map memory.\n");
        goto error_exit;
    }
    vmi_print_hex(memory, PAGE_SIZE);

    retcode = 0;
error_exit:
    if (memory)
        free(memory);
    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    return retcode;
}

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
    if ( argc != 3 )
        return 1;

    vmi_instance_t vmi;
    unsigned char *memory = malloc(PAGE_SIZE);

    /* this is the VM or file that we are looking at */
    char *name = argv[1];

    /* this is the address to map */
    char *addr_str = argv[2];
    addr_t addr = (addr_t) strtoul(addr_str, NULL, 16);

    /* initialize the libvmi library */
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME, NULL,
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

error_exit:
    if (memory)
        free(memory);

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    return 0;
}

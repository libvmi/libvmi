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

#include <stdlib.h>

#include "private.h"

void
vmi_print_hex(
    unsigned char *data,
    unsigned long length)
{
    unsigned long i, j, numrows, index;

    numrows = (length + 15) >> 4;

    for (i = 0; i < numrows; ++i) {
        /* print the byte count */
        printf("%.8lx|  ", i * 16);

        /* print the first 8 hex values */
        for (j = 0; j < 8; ++j) {
            index = i * 16 + j;
            if (index < length) {
                printf("%.2x ", data[index]);
            } else {
                printf("   ");
            }
        }
        printf(" ");

        /* print the second 8 hex values */
        for (; j < 16; ++j) {
            index = i * 16 + j;
            if (index < length) {
                printf("%.2x ", data[index]);
            } else {
                printf("   ");
            }
        }
        printf("  ");

        /* print the ascii values */
        for (j = 0; j < 16; ++j) {
            index = i * 16 + j;
            if (index < length) {
                if (isprint((int) data[index])) {
                    printf("%c", data[index]);
                } else {
                    printf(".");
                }
            }
        }
        printf("\n");
    }
}

void
vmi_print_hex_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    size_t length)
{
    unsigned char *buf = safe_malloc(length);

    if ( VMI_SUCCESS == vmi_read_pa(vmi, paddr, length, buf, NULL) )
        vmi_print_hex(buf, length);
    free(buf);
}

void
vmi_print_hex_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    size_t length)
{
    status_t rc = VMI_FAILURE;
    addr_t paddr = 0;

    if (!pid)
        rc = vmi_translate_kv2p(vmi, vaddr, &paddr);
    else if ( pid > 0 )
        rc = vmi_translate_uv2p(vmi, vaddr, pid, &paddr);

    if ( VMI_SUCCESS == rc )
        vmi_print_hex_pa(vmi, paddr, length);
}

void
vmi_print_hex_ksym(
    vmi_instance_t vmi,
    char *sym,
    size_t length)
{
    addr_t vaddr = 0;

    if ( VMI_SUCCESS == vmi_translate_ksym2v(vmi, sym, &vaddr) )
        vmi_print_hex_va(vmi, vaddr, 0, length);
}

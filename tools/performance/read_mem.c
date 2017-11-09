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
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include "libvmi/libvmi.h"
#include "common.h"

int main(int argc, char **argv)
{
    vmi_instance_t vmi;
    addr_t start_address;
    struct timeval ktv_start;
    struct timeval ktv_end;
    char *vm = argv[1];
    int buf_size = atoi(argv[2]);
    int loops = atoi(argv[3]);
    int mode = atoi(argv[4]);
    unsigned char *buf = malloc(buf_size);
    int i = 0;
    long int diff;
    long int *data = malloc(loops * sizeof(long int));
    int j = 0;

    uint32_t value = 0;
    if (mode != 1 && mode != 2) {
        printf("invalid mode\n");
        return 1;
    }

    /* initialize the xen access library */
    vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, vm);

    /* find address to work from */
    start_address = vmi_translate_ksym2v(vmi, "PsInitialSystemProcess");
    start_address = vmi_translate_kv2p(vmi, start_address);
    for (i = 0; i < loops; ++i) {
        if (mode == 1) {
            gettimeofday(&ktv_start, 0);
            vmi_read_pa(vmi, start_address, buf, buf_size);
            gettimeofday(&ktv_end, 0);
        }

        else {
            gettimeofday(&ktv_start, 0);
            for (j = 0; j < buf_size / 4; ++j) {
                vmi_read_32_pa(vmi, start_address + j * 4, &value);
            }
            gettimeofday(&ktv_end, 0);
        }

        print_measurement(ktv_start, ktv_end, &diff);
        data[i] = diff;
        memset(buf, 0, buf_size);
        sleep(1);
    }
    avg_measurement(data, loops);

    vmi_destroy(vmi);
    free(buf);
    free(data);
    return 0;
}

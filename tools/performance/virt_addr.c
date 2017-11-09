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
    addr_t vaddr;
    struct timeval ktv_start;
    struct timeval ktv_end;
    char *vm = argv[1];
    int loops = atoi(argv[2]);
    int i = 0;
    long int diff;
    long int *data = malloc(loops * sizeof(long int));

    /* initialize the xen access library */
    vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, vm);
    vaddr = vmi_translate_ksym2v(vmi, "PsInitialSystemProcess");
    for (i = 0; i < loops; ++i) {
        gettimeofday(&ktv_start, 0);
        vmi_translate_kv2p(vmi, vaddr);
        gettimeofday(&ktv_end, 0);
        print_measurement(ktv_start, ktv_end, &diff);
        data[i] = diff;
        sleep(2);
    }
    avg_measurement(data, loops);

    vmi_destroy(vmi);
    free(data);
    return 0;
}

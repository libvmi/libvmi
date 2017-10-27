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
#include "xenaccess/xenaccess.h"
#include "common.h"

int main(int argc, char **argv)
{
    xa_instance_t xai;
    xa_linux_taskaddr_t taskaddr;
    unsigned char *memory = NULL;

    uint32_t offset;
    struct timeval ktv_start;
    struct timeval ktv_end;

    uint64_t dom = strtoull(argv[1], NULL, 0);
    vmi_pid_t pid = atoi(argv[2]);
    int loops = atoi(argv[3]);
    int i = 0;
    long int diff;
    long int *data = malloc(loops * sizeof(int));


    /* initialize the xen access library */
    xa_init_vm_id_strict(dom, &xai);
    if (xa_linux_get_taskaddr(&xai, pid, &taskaddr) == XA_FAILURE) {
        perror("failed to get task addresses");
        goto error_exit;
    }

    for (i = 0; i < loops; ++i) {
        gettimeofday(&ktv_start, 0);
        memory = xa_access_user_va(&xai, taskaddr.start_data, &offset, pid, PROT_READ);
        gettimeofday(&ktv_end, 0);
        if (memory == NULL) {
            perror("failed to map memory");
            goto error_exit;
        }

        print_measurement(ktv_start, ktv_end, &diff);
        data[i] = diff;

        if (memory)
            munmap(memory, xai.page_size);
        sleep(2);
    }
    avg_measurement(data, loops);

error_exit:
    xa_destroy(&xai);
    if (memory)
        munmap(memory, xai.page_size);
    return 0;
}



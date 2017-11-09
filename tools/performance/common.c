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
#include "common.h"
#include <stdlib.h>
#include <math.h>

void print_measurement(
    struct timeval ktv_start,
    struct timeval ktv_end,
    long int *diff)
{
    *diff =
        (((long int) ktv_end.tv_usec - (long int) ktv_start.tv_usec) +
         (((long int) ktv_end.tv_sec % 1000000 -
           (long int) ktv_start.tv_sec % 1000000) * 1000000));
    printf("%ld.%.6ld : %ld.%.6ld : %ld\n",
           ((long int) ktv_start.tv_sec) % 1000000,
           (long int) ktv_start.tv_usec,
           ((long int) ktv_end.tv_sec) % 1000000,
           (long int) ktv_end.tv_usec, *diff);
}

static double stddev(
    long int *data,
    int count)
{
    double *sq_data = malloc(count * sizeof(double));
    double total = 0.0;
    double mean = 0.0;
    int i = 0;

    for (i = 0; i < count; ++i) {
        total += (double) data[i];
    }

    mean = total / (double) count;
    for (i = 0; i < count; ++i) {
        sq_data[i] = ((double) data[i]) - mean;
        sq_data[i] *= sq_data[i];
    }

    total = 0.0;
    for (i = 0; i < count; ++i) {
        total += sq_data[i];
    }
    mean = total / (double) count;

    return sqrt(mean);
}

void avg_measurement(
    long int *data,
    int loops)
{
    int i = 0;
    long int sum = 0;

    for (i = 0; i < loops; ++i) {
        sum += data[i];
    }
    printf("mean %f, stdev %f\n",
           (double) ((double) sum / (double) loops), stddev(data, loops));

    // repeat avg for all but first measurement
    sum = 0;
    for (i = 1; i < loops; ++i) {
        sum += data[i];
    }
    printf("mean (dropped first-%ld) %f\n", data[0],
           (double) ((double) sum / ((double) loops - 1.0)));
}

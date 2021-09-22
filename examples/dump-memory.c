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

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <getopt.h>
#include <signal.h>
#include <sys/mman.h>
#include <config.h>
#include <libvmi/libvmi.h>

#define FRAME_SIZE (1UL << 12)
#define PROGRESS_STRIDE (1024 * 1024 * 32) // 32 MiB

/* Create sparse file */
static int sparse_flag;

/* Print progress when dumping the memory */
static int progress_flag;

/* Pause VM when dumping memory */
static int pause_vm_flag = 1;

volatile int interrupted;
void sigint_handler()
{
    interrupted = 1;
}

static int bareflank_setup(vmi_init_data_t **init_data_ptr, memory_map_t **memmap_ptr)
{
    printf("Using this example on Bareflank is not safe.\n");
    printf("You have to adjust it to match your machine before running it.\n");
    return 1;

    /* The following is an example based on the e820 map described in
     * notes/memory_map.txt. */
    uint32_t e820_entries = 5;

    memory_map_t *memmap = malloc(sizeof(memory_map_t) + sizeof(addr_t) * 2 * e820_entries);
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

    vmi_init_data_t *init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
    init_data->count = 1;
    init_data->entry[0].type = VMI_INIT_DATA_MEMMAP;
    init_data->entry[0].data = memmap;
    *init_data_ptr = init_data;
    *memmap_ptr = memmap;
    return 0;
}

static void usage(const char *argv0)
{
    printf("Usage: %s [options] domain output_file\n", argv0);
    printf("Available options:\n");
    printf("  -p, --progress        print progress when dumping\n");
    printf("  -s, --sparse          save dump as sparse file\n");
    printf("      --no-pause        don't pause the VM when dumping memory\n");
    printf("  -k, --kvmi-socket     use the specified kvmi socket for KVM driver\n");
    printf("  -h, --help            print help and exit\n");
}

static const struct option long_opts[] = {
    {"sparse",   no_argument, &sparse_flag,   1},
    {"progress", no_argument, &progress_flag, 1},
    {"no-pause", no_argument, &pause_vm_flag, 0},
    {"kvmi-socket", required_argument, NULL, 'k'},
    {0, 0, 0, 0}
};

int main(int argc, char **argv)
{
    int c;
    int retcode = 1;
    memory_map_t *memmap = NULL;
    vmi_init_data_t *init_data = NULL;
    while ((c = getopt_long(argc, argv, "psk:h", long_opts, NULL)) != -1) {
        switch (c) {
            case 0:
                break;
            case 's':
                sparse_flag = 1;
                break;
            case 'p':
                progress_flag = 1;
                break;
            case 'k':
                // in case we have multiple '-k' argument, avoid memory leak
                if (init_data) {
                    free(init_data->entry[0].data);
                } else {
                    init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
                }
                init_data->count = 1;
                init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
                init_data->entry[0].data = strdup(optarg);
                break;
            case 'h':
            default:
                usage(argv[0]);
                goto free_setup_info;
        }
    }

    /* two other arguments required */
    if (argc - optind != 2) {
        usage(argv[0]);
        goto free_setup_info;
    }

    /* this is the VM or file that we are looking at */
    const char *name = argv[optind];

    /* this is the file name to write the memory image to */
    const char *filename = argv[optind + 1];

    vmi_mode_t mode;
    if (VMI_FAILURE == vmi_get_access_mode(NULL, name, VMI_INIT_DOMAINNAME, init_data, &mode) ) {
        goto free_setup_info;
    }

    /* for bareflank we have to pass-in the actual memory map of the machine. */
    if (mode == VMI_BAREFLANK && bareflank_setup(&init_data, &memmap) != 0) {
        goto free_setup_info;
    }

    /* initialize the libvmi library */
    vmi_instance_t vmi = NULL;
    if (VMI_FAILURE == vmi_init(&vmi, mode, (void*)name, VMI_INIT_DOMAINNAME, init_data, NULL)) {
        printf("Failed to initialize LibVMI library.\n");
        goto free_setup_info;
    }

    /* open the file for writing */
    FILE *f = fopen(filename, "w+");
    if (f == NULL) {
        printf("Failed to open file for writing.\n");
        goto destroy_vmi;
    }

    /* pause the VM */
    if (pause_vm_flag && VMI_FAILURE == vmi_pause_vm(vmi)) {
        printf("Failed to pause the VM.\n");
        goto close_file;
    }

    /* handle ctrl+c gracefully */
    signal(SIGINT, sigint_handler);

    /* dump physical memory */
    char memory[FRAME_SIZE];
    char zeros[FRAME_SIZE];
    memset(zeros, 0, FRAME_SIZE);
    addr_t addr_max = vmi_get_max_physical_address(vmi);
    addr_t address;

    for (address = 0; address < addr_max && !interrupted; address += FRAME_SIZE) {
        if (progress_flag && (address % PROGRESS_STRIDE == 0)) {
            printf("Progress: %lu%%\n", (address * 100) / addr_max);
        }

        int empty_frame = 1;
        /* try to read current frame*/
        if (VMI_SUCCESS == vmi_read_pa(vmi, address, FRAME_SIZE, memory, NULL)) {
            /* check if frame has some non-zero byte */
            if (memcmp(memory, zeros, FRAME_SIZE) != 0) {
                empty_frame = 0;
            }
        }

        /* skip empty frame in sparse mode*/
        if (sparse_flag && empty_frame) {
            int status = fseek(f, FRAME_SIZE, SEEK_CUR);
            if (status != 0) {
                printf("Failed to fseek FRAME_SIZE into file.\n");
                goto resume_vm;
            }
            continue;
        }

        /* write frame to output file */
        char *buffer = empty_frame ? zeros : memory;
        size_t written = fwrite(buffer, 1, FRAME_SIZE, f);
        if (written != FRAME_SIZE) {
            printf("Failed to saved frame.\n");
            goto resume_vm;
        }
    }

    retcode = 0;
resume_vm:
    if (pause_vm_flag) {
        vmi_resume_vm(vmi);
    }

close_file:
    fclose(f);

destroy_vmi:
    vmi_destroy(vmi);

free_setup_info:
    free(memmap);
    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }
    return retcode;
}

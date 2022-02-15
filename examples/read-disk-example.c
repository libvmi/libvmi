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
#include <sys/mman.h>
#include <config.h>
#include <libvmi/libvmi.h>

#define SECTOR_SIZE 512

int main(int argc, char **argv)
{
    vmi_init_data_t *init_data = NULL;
    uint64_t domid = 0;
    uint8_t init = VMI_INIT_DOMAINNAME;
    void *domain = NULL;
    void *filename = NULL;
    int retcode = 1;
    unsigned int number_of_disks = 0;
    bool bootable = false;
    unsigned char MBR[SECTOR_SIZE] = {0};
    
    if ( argc <= 2 ) {
        printf("Usage: %s\n", argv[0]);
        printf("\t -n/--name <domain name>\n");
        printf("\t -d/--domid <domain id>\n\n");
        printf("\t -f/--file <file name>");
        return false;
    }

    const struct option long_opts[] = {
        {"name", required_argument, NULL, 'n'},
        {"domid", required_argument, NULL, 'd'},
        {"file", required_argument, NULL, 'f'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "n:d:f:";
    int c;
    int long_index = 0;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
        switch (c) {
            case 'n':
                domain = optarg;
                break;
            case 'd':
                init = VMI_INIT_DOMAINID;
                domid = strtoull(optarg, NULL, 0);
                domain = (void*)&domid;
                break;
            case 'f':
                filename = optarg;
                break;
            default:
                printf("Unknown option\n");
                return false;
        }

    vmi_mode_t mode;
    if (VMI_FAILURE == vmi_get_access_mode(NULL, domain, VMI_INIT_DOMAINNAME, init_data, &mode) ) {
        goto free_setup_info;
    }

    if (VMI_XEN != mode) {
        printf("Disk reading available only for Xen VM.\n");
        goto free_setup_info;
    }

    /* initialize the libvmi library */
    vmi_instance_t vmi = NULL;
    if (VMI_FAILURE == vmi_init(&vmi, mode, (void*)domain, VMI_INIT_DOMAINNAME, init_data, NULL)) {
        printf("Failed to initialize LibVMI library.\n");
        goto free_setup_info;
    }

    /* open the file for writing */
    FILE *f = fopen(filename, "w+");
    if (f == NULL) {
        printf("Failed to open file for writing.\n");
        goto destroy_vmi;
    }

    if (VMI_FAILURE == vmi_pause_vm(vmi)) {
        printf("Failed to pause the VM.\n");
        goto close_file;
    }

    /* Get VM disks identificators */
    char **devices_ids = vmi_get_disks(vmi, &number_of_disks);
    if (!devices_ids) {
        printf("Failed to get VM disks list.\n");
        goto resume_vm;
    }
    
    /* Iterate over disks to find bootable and read MBR sector */
    for (unsigned int i = 0; i < number_of_disks; i++) {
        if (VMI_FAILURE == vmi_disk_is_bootable(vmi, devices_ids[i], &bootable)) {
            printf("Failed to check bootable flag.\n");
            goto free_devices_list;
        }

        if (bootable) {
            if (VMI_SUCCESS == vmi_read_disk(vmi, devices_ids[i], 0, SECTOR_SIZE, MBR)) {
                if (SECTOR_SIZE == fwrite(MBR, 1, SECTOR_SIZE, f)) {
                    printf("MBR successfuly dumped\n");
                    break;
                }
            }
            else {
                printf("Faied to read disk %u MBR.\n", i);
                break;
            }
        }
    }

    retcode = 0;

free_devices_list:
    free(devices_ids);

resume_vm:
    vmi_resume_vm(vmi);

close_file:
    fclose(f);

destroy_vmi:
    vmi_destroy(vmi);

free_setup_info:
    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }
    return retcode;
}

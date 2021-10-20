/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Manorit Chawdhry (manorit2001@gmail.com)
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

#define LIBVMI_EXTRA_JSON

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <libvmi/events.h>
#include <libvmi/libvmi_extra.h>

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>
#include <glib.h>
#include <signal.h>
#include <unistd.h>

vmi_instance_t vmi;

void clean_up(void)
{
    vmi_destroy(vmi);
}

void sigint_handler()
{
    clean_up();
    exit(1);
}

void show_usage(char *arg0)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s [OPTIONS...]\n", arg0);
    fprintf(stderr, "\n");
    fprintf(stderr, "Required one of:\n");
    fprintf(stderr, "    -n, --name           Domain name\n");
    fprintf(stderr, "    -d, --domid          Domain ID\n");
    fprintf(stderr, "Required input:\n");
    fprintf(stderr, "    -r, --json-kernel    The OS kernel's json profile\n");
    fprintf(stderr, "Optional input:\n");
    fprintf(stderr, "    -k, --only-kpgd      Only print KPGD value\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "    %s -n lin7vm -r /opt/kernel.json\n", arg0);
    fprintf(stderr, "    %s --domid 17 --json-kernel /opt/kernel.json --only-kpgd\n", arg0);
}

int main(int argc, char **argv)
{
    void *domain = NULL;
    uint64_t domid = VMI_INVALID_DOMID;
    uint64_t init_flags = 0;
    int only_output_kpgd = 0;

    char *kernel_profile = NULL;
    int long_index = 0;
    char c;

    const struct option long_opts[] = {
        {"name", required_argument, NULL, 'n'},
        {"domid", required_argument, NULL, 'd'},
        {"json-kernel", required_argument, NULL, 'r'},
        {"only-kpgd", no_argument, NULL, 'k'},
    };

    while ((c = getopt_long (argc, argv, "n:d:kr:", long_opts, &long_index)) != -1)
        switch (c) {
            case 'n':
                domain = (void *)optarg;
                init_flags |= VMI_INIT_DOMAINNAME;
                break;
            case 'd':
                domid = strtoull(optarg, NULL, 0);
                domain = (void *)&domid;
                init_flags |= VMI_INIT_DOMAINID;
                break;
            case 'k':
                only_output_kpgd = 1;
                break;
            case 'r':
                kernel_profile = optarg;
                break;
            default:
                show_usage(argv[0]);
                return 1;
        }

    if (optind != argc) {
        fprintf(stderr, "Unrecognized argument: %s\n", argv[optind]);
        show_usage(argv[0]);
        return 1;
    }

    if (!domain) {
        fprintf(stderr, "You have to specify --name or --domid!\n");
        show_usage(argv[0]);
        return 1;
    }

    if ((init_flags & VMI_INIT_DOMAINNAME) && (init_flags & VMI_INIT_DOMAINID)) {
        fprintf(stderr, "Both domain ID and domain name provided!\n");
        show_usage(argv[0]);
        return 1;
    }

    if (!kernel_profile) {
        fprintf(stderr, "You have to specify path to kernel JSON profile!\n");
        show_usage(argv[0]);
        return 1;
    }

    vmi_mode_t mode;

    if (VMI_FAILURE == vmi_get_access_mode(vmi, domain, init_flags, NULL, &mode)) {
        printf("Failed to get access mode\n");
        goto done;
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, domain, init_flags, NULL, NULL)) {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        goto done;
    }

    signal(SIGINT, sigint_handler);

    os_t os = vmi_init_os(vmi, VMI_CONFIG_JSON_PATH, kernel_profile, NULL);

    if (VMI_OS_LINUX != os) {
        fprintf(stderr, "OS is not Linux\n");
        goto done;
    }

    /* Get internal fields */
    addr_t linux_tasks = 0;
    addr_t linux_mm = 0;
    addr_t linux_pid = 0;
    addr_t linux_name = 0;
    addr_t linux_pgd  = 0;
    addr_t linux_kaslr = 0;
    addr_t linux_init_task = 0;
    addr_t kpgd = 0;

    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_tasks", &linux_tasks))
        fprintf(stderr, "Failed to read field \"linux_tasks\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_mm", &linux_mm))
        fprintf(stderr, "Failed to read field \"linux_mm\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_pid", &linux_pid))
        fprintf(stderr, "Failed to read field \"linux_pid\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_name", &linux_name))
        fprintf(stderr, "Failed to read field \"linux_name\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_pgd", &linux_pgd))
        fprintf(stderr, "Failed to read field \"linux_pgd\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_kaslr", &linux_kaslr))
        fprintf(stderr, "Failed to read field \"linux_kaslr\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_init_task", &linux_init_task))
        fprintf(stderr, "Failed to read field \"linux_init_task\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "kpgd", &kpgd))
        fprintf(stderr, "Failed to read field \"kpgd\"\n");

    if (only_output_kpgd) {
        printf("0x%lx\n", kpgd);
    } else {
        printf("linux_tasks:0x%lx\n"
               "linux_mm:0x%lx\n"
               "linux_pid:0x%lx\n"
               "linux_name:0x%lx\n"
               "linux_pgd:0x%lx\n"
               "linux_kaslr:0x%lx\n"
               "linux_init_task:0x%lx\n"
               "kpgd:0x%lx\n",
               linux_tasks,
               linux_mm,
               linux_pid,
               linux_name,
               linux_pgd,
               linux_kaslr,
               linux_init_task,
               kpgd);
    }

    if (!kpgd) {
        fprintf(stderr, "Failed to get most essential fields\n");
        goto done;
    }

    vmi_resume_vm(vmi);

    return 0;

done:
    clean_up();

    return 1;
}

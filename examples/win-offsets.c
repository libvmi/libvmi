/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Sergey Kovalev (valor@list.ru)
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

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>
#include <glib.h>


int main(int argc, char **argv)
{
    GHashTable* config = NULL;
    vmi_instance_t vmi = NULL;
    vmi_mode_t mode;
    uint64_t init_flags = 0;
    vmi_init_data_t *init_data = NULL;
    uint64_t domid = 0;
    void* domain = NULL;
    char *profile = NULL;

    int rc = 1;

    if ( argc < 2 ) {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        fprintf(stderr, "\t -n/--name <domain name>\n");
        fprintf(stderr, "\t -d/--domid <domain id>\n");
        fprintf(stderr, "\t -j/--json <path to kernel's json profile>\n");
        fprintf(stderr, "\t -s/--socket <path to KVMI socket>\n");
        return rc;
    }

    // parse options
    const struct option long_opts[] = {
        {"name", required_argument, NULL, 'n'},
        {"domid", required_argument, NULL, 'd'},
        {"json", required_argument, NULL, 'j'},
        {"socket", optional_argument, NULL, 's'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "n:d:j:s:";
    int c;
    int long_index = 0;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
        switch (c) {
            case 'n':
                domain = optarg;
                init_flags = VMI_INIT_DOMAINNAME;
                break;
            case 'd':
                init_flags = VMI_INIT_DOMAINID;
                domid = strtoull(optarg, NULL, 0);
                domain = (void*)&domid;
                break;
            case 'j':
                profile = (char*)optarg;
                break;
            case 's':
                init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
                init_data->count = 1;
                init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
                init_data->entry[0].data = strdup(optarg);
                break;
            default:
                printf("Unknown option\n");
                return rc;
        }

    if (VMI_FAILURE == vmi_get_access_mode(vmi, domain, init_flags, init_data, &mode)) {
        printf("Failed to get access mode\n");
        goto done;
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, domain, init_flags, init_data, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto done;
    }

    /* pause the vm for consistent memory access */
    if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to pause VM\n");
        goto done;
    } // if

    config = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    if (!config) {
        printf("Failed to create GHashTable!\n");
        goto done;
    }

    g_hash_table_insert(config, g_strdup("os_type"), g_strdup("Windows"));
    g_hash_table_insert(config, g_strdup("rekall_profile"), g_strdup(profile));

    if (VMI_PM_UNKNOWN == vmi_init_paging(vmi, VMI_PM_INITFLAG_TRANSITION_PAGES) ) {
        printf("Failed to init LibVMI paging.\n");
        goto done;
    }

    os_t os = vmi_init_os(vmi, VMI_CONFIG_GHASHTABLE, config, NULL);
    if (VMI_OS_WINDOWS != os) {
        printf("Failed to init LibVMI library.\n");
        goto done;
    }

    /* Get internal fields */
    addr_t ntoskrnl = 0;
    addr_t ntoskrnl_va = 0;
    addr_t tasks = 0;
    addr_t pdbase = 0;
    addr_t pid = 0;
    addr_t pname = 0;
    addr_t kdvb = 0;
    addr_t sysproc = 0;
    addr_t kpcr = 0;
    addr_t kdbg = 0;
    addr_t kpgd = 0;

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_ntoskrnl", &ntoskrnl))
        printf("Failed to read field \"ntoskrnl\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_ntoskrnl_va", &ntoskrnl_va))
        printf("Failed to read field \"ntoskrnl_va\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks))
        printf("Failed to read field \"tasks\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_pdbase", &pdbase))
        printf("Failed to read field \"pdbase\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_pid", &pid))
        printf("Failed to read field \"pid\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_pname", &pname))
        printf("Failed to read field \"pname\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_kdvb", &kdvb))
        printf("Failed to read field \"kdvb\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_sysproc", &sysproc))
        printf("Failed to read field \"sysproc\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_kpcr", &kpcr))
        printf("Failed to read field \"kpcr\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_kdbg", &kdbg))
        printf("Failed to read field \"kdbg\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "kpgd", &kpgd))
        printf("Failed to read field \"kpgd\"\n");

    printf("win_ntoskrnl:0x%lx\n"
           "win_ntoskrnl_va:0x%lx\n"
           "win_tasks:0x%lx\n"
           "win_pdbase:0x%lx\n"
           "win_pid:0x%lx\n"
           "win_pname:0x%lx\n"
           "win_kdvb:0x%lx\n"
           "win_sysproc:0x%lx\n"
           "win_kpcr:0x%lx\n"
           "win_kdbg:0x%lx\n"
           "kpgd:0x%lx\n",
           ntoskrnl,
           ntoskrnl_va,
           tasks,
           pdbase,
           pid,
           pname,
           kdvb,
           sysproc,
           kpcr,
           kdbg,
           kpgd);

    if (!ntoskrnl || !ntoskrnl_va || !sysproc || !pdbase || !kpgd) {
        printf("Failed to get most essential fields\n");
        goto done;
    }

    rc = 0;

    /* cleanup any memory associated with the LibVMI instance */
done:
    /* resume the vm */
    vmi_resume_vm(vmi);

    vmi_destroy(vmi);

    if (config)
        g_hash_table_destroy(config);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return rc;
}

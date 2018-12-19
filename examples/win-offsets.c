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
#include <libvmi/os/windows/windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <glib.h>


int main(int argc, char **argv)
{

    vmi_instance_t vmi = NULL;
    vmi_mode_t mode;

    /* this is the VM that we are looking at */
    if (argc != 5) {
        printf("Usage: %s name|domid <domain name|domain id> -r <rekall profile>\n", argv[0]);
        return 1;
    }   // if

    void *domain;
    uint64_t domid = VMI_INVALID_DOMID;
    uint64_t init_flags = 0;

    if (strcmp(argv[1],"name")==0) {
        domain = (void*)argv[2];
        init_flags |= VMI_INIT_DOMAINNAME;
    } else if (strcmp(argv[1],"domid")==0) {
        domid = strtoull(argv[2], NULL, 0);
        domain = (void*)&domid;
        init_flags |= VMI_INIT_DOMAINID;
    } else {
        printf("You have to specify either name or domid!\n");
        return 1;
    }

    char *rekall_profile = NULL;

    if (strcmp(argv[3], "-r") == 0) {
        rekall_profile = argv[4];
    } else {
        printf("You have to specify path to rekall profile!\n");
        return 1;
    }

    if (VMI_FAILURE == vmi_get_access_mode(vmi, domain, init_flags, NULL, &mode) )
        return 1;

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, domain, init_flags, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    GHashTable* config = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    if (!config) {
        printf("Failed to create GHashTable!\n");
        return 1;
    }

    g_hash_table_insert(config, g_strdup("os_type"), g_strdup("Windows"));
    g_hash_table_insert(config, g_strdup("rekall_profile"), g_strdup(rekall_profile));

    if (VMI_PM_UNKNOWN == vmi_init_paging(vmi, VMI_PM_INITFLAG_TRANSITION_PAGES) ) {
        printf("Failed to init LibVMI paging.\n");
        g_hash_table_destroy(config);
        return 1;
    }

    vmi_init_os(vmi, VMI_CONFIG_GHASHTABLE, config, NULL);

    windows_instance_t windows = vmi->os_data;
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
           "rekall_profile:\"%s\"\n"
           "ostype:\"Windows\"\n",
           windows->ntoskrnl,
           windows->ntoskrnl_va,
           windows->tasks_offset,
           windows->pdbase_offset,
           windows->pid_offset,
           windows->pname_offset,
           windows->kdbg_va,
           windows->sysproc,
           windows->kpcr_offset,
           windows->kdbg_offset,
           windows->rekall_profile);

    /* cleanup any memory associated with the LibVMI instance */
    g_hash_table_destroy(config);
    vmi_destroy(vmi);

    return 0;
}

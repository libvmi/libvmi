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
#include <glib.h>


int main(int argc, char **argv)
{
    GHashTable* config = NULL;
    vmi_instance_t vmi = NULL;
    vmi_mode_t mode;
    int rc = 1;

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
    g_hash_table_insert(config, g_strdup("rekall_profile"), g_strdup(rekall_profile));

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

    return rc;
}

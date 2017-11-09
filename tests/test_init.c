/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2012 VMITools Project
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

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <glib.h>
#include "../libvmi/libvmi.h"
#include "check_tests.h"

/* test init_complete for Windows from Rekall sysmap */
START_TEST (test_libvmi_init4)
{
    const char *name = get_testvm();
    vmi_instance_t vmi = NULL;
    vmi_init_complete(&vmi, (void*)name, VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    if (VMI_OS_WINDOWS == vmi_get_ostype(vmi) && VMI_OS_WINDOWS_XP == vmi_get_winver(vmi)) {
        char location[100];
        getcwd(location, sizeof(location));

#define XP_REKALL_PROFILE_LIVE "ntkrnlpa.pdb.bd8f451f3e754ed8a34b50560ceb08e31.rekall.json"
#define XP_REKALL_PROFILE_FILE "ntoskrnl.pdb.32962337f0f646388b39535cd8dd70e82.rekall.json"

        char *rekall_profile = NULL;
        vmi_mode_t mode;
        if (VMI_FAILURE == vmi_get_access_mode(vmi, NULL, 0, NULL, &mode))
            goto done;

        if ( mode == VMI_FILE) {
            rekall_profile = g_malloc0(snprintf(NULL,0,"%s/%s", location, XP_REKALL_PROFILE_FILE)+1);
            sprintf(rekall_profile, "%s/%s", location, XP_REKALL_PROFILE_FILE);
        } else {
            rekall_profile = g_malloc0(snprintf(NULL,0,"%s/%s", location, XP_REKALL_PROFILE_LIVE)+1);
            sprintf(rekall_profile, "%s/%s", location, XP_REKALL_PROFILE_LIVE);
        }

        vmi_destroy(vmi);

        GHashTable *config = g_hash_table_new(g_str_hash, g_str_equal);
        g_hash_table_insert(config, "ostype", "Windows");
        g_hash_table_insert(config, "rekall_profile", rekall_profile);
        if (VMI_FAILURE == vmi_init_complete(&vmi, (void*)name, VMI_INIT_DOMAINNAME, NULL,
                                             VMI_CONFIG_GHASHTABLE, config, NULL)) {
            fail_unless(0, "failed to init XP test domain from Rekall profile %s.", rekall_profile);
        }
        g_hash_table_destroy(config);
        g_free(rekall_profile);
    }

done:
    vmi_destroy(vmi);
}
END_TEST

/* test init_complete with passed config */
START_TEST (test_libvmi_init3)
{
    FILE *f = NULL;
    const char *ptr = NULL;
    char location[100];
    const char *sudo_user = NULL;
    struct passwd *pw_entry = NULL;
    vmi_instance_t vmi = NULL;

    /* read the config entry from the config file */
    /* first check home directory of sudo user */
    if ((sudo_user = getenv("SUDO_USER")) != NULL) {
        if ((pw_entry = getpwnam(sudo_user)) != NULL) {
            snprintf(location, 100, "%s/etc/libvmi.conf\0",
                     pw_entry->pw_dir);
            if ((f = fopen(location, "r")) != NULL) {
                goto success;
            }
        }
    }

    /* next check home directory for current user */
    snprintf(location, 100, "%s/etc/libvmi.conf\0", getenv("HOME"));
    if ((f = fopen(location, "r")) != NULL) {
        goto success;
    }

    /* finally check in /etc */
    snprintf(location, 100, "/etc/libvmi.conf\0");
    if ((f = fopen(location, "r")) != NULL) {
        goto success;
    }

    fail_unless(0, "failed to find config file");
success:

    /* strip path for memory image files */
    if ((ptr = strrchr(get_testvm(), '/')) == NULL) {
        ptr = get_testvm();
    } else {
        ptr++;
    }

    /* check file size */
    fseek(f, 0L, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0L, SEEK_SET);

    /* read entry in from file */
    char *buf = malloc(sz);
    fread(buf, sz, 1, f);
    long pos = 0;
    size_t max_len = strnlen(ptr, 100);
    int found = 0;
    for (pos = 0; pos < sz; ++pos) {
        if (strncmp(buf + pos, ptr, max_len) == 0) {
            found = 1;
            break;
        }
    }
    if (!found) {
        fail_unless(0, "failed to find config entry");
    }
    long start = pos + max_len;
    found = 0;
    for ( ; pos < sz; ++pos) {
        if (buf[pos] == '}') {
            found = 1;
            break;
        }
    }
    if (!found) {
        fail_unless(0, "failed to find end of config entry");
    }
    long end = pos + 1;
    long entry_length = end - start;
    char *config = malloc(entry_length);
    memcpy(config, buf + start, entry_length);
    free(buf);

    status_t ret = vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                                     VMI_CONFIG_STRING, (void*)config, NULL);
    free(config);

    fail_unless(ret == VMI_SUCCESS,
                "vmi_init_complete failed");
    fail_unless(vmi != NULL,
                "vmi_init_complete failed to initialize vmi instance struct");
    vmi_destroy(vmi);
}
END_TEST

/* test determine mode and init function */
START_TEST (test_libvmi_init2)
{
    vmi_instance_t vmi = NULL;
    vmi_mode_t mode;
    status_t ret = vmi_get_access_mode(vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL, &mode);
    fail_unless(ret == VMI_SUCCESS,
                "vmi_get_access_mode failed to identify the hypervisor");
    ret = vmi_init(&vmi, mode, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL, NULL);
    fail_unless(ret == VMI_SUCCESS,
                "vmi_init failed");
    fail_unless(vmi != NULL,
                "vmi_init failed to initialize vmi instance struct");
    vmi_destroy(vmi);
}
END_TEST

/* test auto complete init */
START_TEST (test_libvmi_init1)
{
    vmi_instance_t vmi = NULL;
    status_t ret = vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                                     VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    fail_unless(ret == VMI_SUCCESS,
                "vmi_init failed with VMI_INIT_DOMAINNAME and global config");
    fail_unless(vmi != NULL,
                "vmi_init failed to initialize vmi instance struct");
    vmi_destroy(vmi);
}
END_TEST

/* init test cases */
TCase *init_tcase (void)
{
    TCase *tc_init = tcase_create("LibVMI Init");
    tcase_add_test(tc_init, test_libvmi_init1);
    tcase_add_test(tc_init, test_libvmi_init2);
    tcase_add_test(tc_init, test_libvmi_init3);

#ifdef REKALL_PROFILES
    tcase_add_test(tc_init, test_libvmi_init4);
#endif

    return tc_init;
}

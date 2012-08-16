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
#include "../libvmi/libvmi.h"

/* VM name to test against */
char *testvm = NULL;

/* test vmi_translate_ksym2v */
START_TEST (test_libvmi_ksym2v)
{
    vmi_instance_t vmi = NULL;
    status_t ret = vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, testvm);
    addr_t va = 0;
    if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)){
        va = vmi_translate_ksym2v(vmi, "PsInitialSystemProcess");
    }
    else if (VMI_OS_LINUX == vmi_get_ostype(vmi)){
        va = vmi_translate_ksym2v(vmi, "init_task");
    }
    else{
        fail_unless(0, "vmi set to invalid os type");
    }
    fail_unless(va != 0, "ksym2v translation failed");
    vmi_destroy(vmi);
}
END_TEST

/* test init_complete with passed config */
START_TEST (test_libvmi_init3)
{
    FILE *f = NULL;
    char *ptr = NULL;
    char location[100];
    char *sudo_user = NULL;
    struct passwd *pw_entry = NULL;
    vmi_instance_t vmi = NULL;
    status_t ret = vmi_init(&vmi, VMI_AUTO | VMI_INIT_PARTIAL, testvm);
    
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
    if ((ptr = strrchr(testvm, '/')) == NULL) {
        ptr = testvm;
    }
    else {
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
    for (pos = 0; pos < sz; ++pos){
        if (strncmp(buf + pos, ptr, max_len) == 0){
            found = 1;
            break;
        }
    }
    if (!found){
        fail_unless(0, "failed to find config entry");
    }
    long start = pos + max_len;
    found = 0;
    for ( ; pos < sz; ++pos){
        if (buf[pos] == '}'){
            found = 1;
            break;
        }
    }
    if (!found){
        fail_unless(0, "failed to find end of config entry");
    }
    long end = pos + 1;
    long entry_length = end - start;
    char *config = malloc(entry_length);
    memcpy(config, buf + start, entry_length);
    free(buf);

    /* complete the init */
    ret = vmi_init_complete(&vmi, config);
    free(config);
    fail_unless(ret == VMI_SUCCESS,
                "vmi_init_complete failed");
    fail_unless(vmi != NULL,
                "vmi_init_complete failed to initialize vmi instance struct");
    vmi_destroy(vmi);
}
END_TEST

/* test partial init and init_complete function */
START_TEST (test_libvmi_init2)
{
    vmi_instance_t vmi = NULL;
    status_t ret = vmi_init(&vmi, VMI_AUTO | VMI_INIT_PARTIAL, testvm);
    fail_unless(ret == VMI_SUCCESS,
                "vmi_init failed with AUTO | PARTIAL");
    fail_unless(vmi != NULL,
                "vmi_init failed to initialize vmi instance struct");
    ret = vmi_init_complete(&vmi, NULL);
    fail_unless(ret == VMI_SUCCESS,
                "vmi_init_complete failed");
    fail_unless(vmi != NULL,
                "vmi_init_complete failed to initialize vmi instance struct");
    vmi_destroy(vmi);
}
END_TEST

/* test auto complete init */
START_TEST (test_libvmi_init1)
{
    vmi_instance_t vmi = NULL;
    status_t ret = vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, testvm);
    fail_unless(ret == VMI_SUCCESS,
                "vmi_init failed with AUTO | COMPLETE");
    fail_unless(vmi != NULL,
                "vmi_init failed to initialize vmi instance struct");
    vmi_destroy(vmi);
}
END_TEST

Suite *
libvmi_suite (void)
{
    Suite *s = suite_create("LibVMI");

    /* init test cases */
    TCase *tc_init = tcase_create("LibVMI Init");
    tcase_add_test(tc_init, test_libvmi_init1);
    tcase_add_test(tc_init, test_libvmi_init2);
    tcase_add_test(tc_init, test_libvmi_init3);
    suite_add_tcase(s, tc_init);

    /* translate test cases */
    TCase *tc_translate = tcase_create("LibVMI Translate");
    tcase_add_test(tc_translate, test_libvmi_ksym2v);
    // uv2p
    // kv2p
    // pid_to_dtb
    suite_add_tcase(s, tc_translate);

    return s;
}

int
main (void)
{
    /* get the vm name to test against */
    //TODO allow a list of names in this variable
    testvm = getenv("LIBVMI_CHECK_TESTVM");
    if (NULL == testvm) {
        printf("!! Check requires VM name to test against.\n");
        printf("!! Store name in env variable 'LIBVMI_CHECK_TESTVM'.\n");
        return 1;
    }

    int number_failed = 0;
    Suite *s = libvmi_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    if (number_failed == 0) {
        return EXIT_SUCCESS;
    }
    else {
        return EXIT_FAILURE;
    }
}

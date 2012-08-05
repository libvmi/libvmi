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
#include "../libvmi/libvmi.h"

/* VM name to test against */
char *testvm = NULL;

/* test init_complete with passed config */
START_TEST (test_libvmi_init3)
{
    char config[1024];
    vmi_instance_t vmi = NULL;
    status_t ret = vmi_init(&vmi, VMI_AUTO | VMI_INIT_PARTIAL, testvm);
    
    //TODO make this work for arbitrary VMs
    strcat(config, "{");
    strcat(config, " sysmap = \"/boot/vm/System.map-3.2.0-23-generic\";");
    strcat(config, " ostype = \"Linux\";");
    strcat(config, " linux_name = 0x460;");
    strcat(config, " linux_tasks = 0x238;");
    strcat(config, " linux_mm = 0x270;");
    strcat(config, " linux_pid = 0x2ac;");
    strcat(config, " linux_pgd = 0x50;");
    strcat(config, " linux_addr = 0xf0;");
    strcat(config, "}");
    ret = vmi_init_complete(&vmi, config);
    fail_unless(ret == VMI_SUCCESS,
                "vmi_init_complete failed");
    fail_unless(vmi != NULL,
                "vmi_init_complete failed to initialize vmi instance struct");
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
    //tcase_add_test(tc_init, test_libvmi_init3);
    suite_add_tcase(s, tc_init);

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

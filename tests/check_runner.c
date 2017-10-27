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
#include <stdio.h>
#include "check_tests.h"
#include "../libvmi/libvmi.h"

TCase *init_tcase();
TCase *translate_tcase();
TCase *read_tcase();
TCase *write_tcase();
TCase *print_tcase();
TCase *accessor_tcase();
TCase *util_tcase();
TCase *peparse_tcase();
TCase *cache_tcase();
TCase *get_va_pages_tcase();
TCase *shm_snapshot_tcase();

const char *testvm = NULL;

const char *get_testvm (void)
{
    return testvm;
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

    /* setup the test suite */
    int number_failed = 0;
    Suite *s = suite_create("LibVMI");

    /* add test cases */
    suite_add_tcase(s, init_tcase());
    suite_add_tcase(s, translate_tcase());
    suite_add_tcase(s, read_tcase());
    suite_add_tcase(s, write_tcase());
    suite_add_tcase(s, print_tcase());
    suite_add_tcase(s, accessor_tcase());
    suite_add_tcase(s, util_tcase());
    suite_add_tcase(s, peparse_tcase());
    suite_add_tcase(s, cache_tcase());
    suite_add_tcase(s, get_va_pages_tcase());

#if ENABLE_SHM_SNAPSHOT == 1
    suite_add_tcase(s, shm_snapshot_tcase());
#endif

    /* run the tests */
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    if (number_failed == 0) {
        return EXIT_SUCCESS;
    } else {
        return EXIT_FAILURE;
    }
}

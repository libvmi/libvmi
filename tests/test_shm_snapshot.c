/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2012 VMITools Project
 *
 * Author: Bryan D. Payne (bdpayne@acm.org), Guanglin Xu (mzguanglin@gmail.com)
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
#include "check_tests.h"


/* test vmi_snapshot_create */
START_TEST (test_libvmi_shm_snapshot_create)
{
    vmi_instance_t vmi = NULL;
    status_t ret = vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, get_testvm());

#if ENABLE_SNAPSHOT == 1
    ret = vmi_snapshot_create(vmi);
#endif

    fail_unless(ret == VMI_SUCCESS,
                "vmi_init failed with AUTO | COMPLETE");
    fail_unless(vmi != NULL,
                "vmi_init failed to initialize vmi instance struct");
    vmi_destroy(vmi);
}
END_TEST

/* snapshot test cases */
TCase *shm_snapshot_tcase (void)
{
    TCase *tc_init = tcase_create("LibVMI shm-snapshot");
    tcase_add_test(tc_init, test_libvmi_shm_snapshot_create);
    return tc_init;
}

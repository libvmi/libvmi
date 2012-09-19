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
#include "check_tests.h"


/* test vmi_translate_ksym2v */
START_TEST (test_libvmi_ksym2v)
{
    vmi_instance_t vmi = NULL;
    status_t ret = vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, get_testvm());
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

/* translate test cases */
TCase *translate_tcase (void)
{
    TCase *tc_translate = tcase_create("LibVMI Translate");
    tcase_add_test(tc_translate, test_libvmi_ksym2v);
    // uv2p
    // kv2p
    // pid_to_dtb
    return tc_translate;
}

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
#include "../libvmi/libvmi.h"
#include "check_tests.h"


START_TEST (test_vmi_read_ksym)
{
    vmi_instance_t vmi = NULL;
    char *sym = NULL;
    char *buf = malloc(100);
    size_t count = 100;
    vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, get_testvm());
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
        sym = "init_task";
    }
    else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {
        sym = "PsInitialSystemProcess";
    }
    size_t read = vmi_read_ksym(vmi, sym, buf, count);
    fail_unless(read == count, "vmi_read_ksym failed");
    free(buf);
    vmi_destroy(vmi);
}
END_TEST

/* read test cases */
TCase *read_tcase (void)
{
    TCase *tc_read = tcase_create("LibVMI Read");
    tcase_add_test(tc_read, test_vmi_read_ksym);
    // vmi_read_va
    // vmi_read_pa

    // vmi_read_8_ksym
    // vmi_read_16_ksym
    // vmi_read_32_ksym
    // vmi_read_64_ksym
    // vmi_read_addr_ksym
    // vmi_read_str_ksym

    // vmi_read_8_va
    // vmi_read_16_va
    // vmi_read_32_va
    // vmi_read_64_va
    // vmi_read_addr_va
    // vmi_read_str_va
    // vmi_read_unicode_str_va
    // vmi_convert_str_encoding
    // vmi_free_unicode_str
   
    // vmi_read_8_pa
    // vmi_read_16_pa
    // vmi_read_32_pa
    // vmi_read_64_pa
    // vmi_read_addr_pa
    // vmi_read_str_pa
  
    return tc_read;
}

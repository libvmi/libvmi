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

#include <stdlib.h>
#include <string.h>
#include <check.h>
#include "../libvmi/libvmi.h"
#include "check_tests.h"


START_TEST (test_vmi_get_name)
{
    vmi_instance_t vmi = NULL;
    char *name = NULL;
    int compare = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    name = vmi_get_name(vmi);
    compare = strcmp(name, get_testvm());
    fail_unless(compare == 0, "vmi_get_name failed");
    free(name);
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_get_memsize_max_phys_addr)
{
    vmi_instance_t vmi = NULL;
    uint64_t memsize = 0;
    addr_t max_physical_addr = 0;

    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);

    memsize = vmi_get_memsize(vmi);
    max_physical_addr = vmi_get_max_physical_address(vmi);

    fail_unless(memsize > 0, "guest ram size is 0");
    fail_unless(max_physical_addr > 0, "max physical address is 0");

    fail_unless(max_physical_addr >= memsize, "max physical address is less than memsize");

    vmi_destroy(vmi);
}
END_TEST

/* accessor test cases */
TCase *accessor_tcase (void)
{
    TCase *tc_accessor = tcase_create("LibVMI Accessor");

    tcase_add_test(tc_accessor, test_vmi_get_name);
    tcase_add_test(tc_accessor, test_vmi_get_memsize_max_phys_addr);
    //vmi_get_vmid
    //vmi_get_access_mode
    //vmi_get_page_mode
    //vmi_get_ostype
    //vmi_get_winver
    //vmi_get_winver_str
    //vmi_get_offset
    //vmI_get_memsize
    //vmi_get_vcpureg

    return tc_accessor;
}

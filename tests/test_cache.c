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
#include "../libvmi/private.h"

/* test cache */
START_TEST (test_libvmi_cache)
{
    vmi_instance_t vmi = NULL;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);

    v2p_cache_flush(vmi, ~0ull);
    v2p_cache_set(vmi, 0x400000, 0xabcde, 0x3b40a000);

    addr_t pa = 0;
    status_t ret = v2p_cache_get(vmi, 0x880000400000ull, 0xabcde, &pa);
    fail_if(ret == VMI_SUCCESS, "hit a wrong cache");

    /* @awsaba 's complementary */
    ret = v2p_cache_get(vmi, 0x00000400000ull, 0xabcde, &pa);
    fail_if(ret == VMI_FAILURE, "cache entry not found");

    v2p_cache_flush(vmi, ~0ull);
    vmi_destroy(vmi);
}
END_TEST

/* cache test cases */
TCase *cache_tcase (void)
{
    TCase *tc_init = tcase_create("LibVMI cache");
    tcase_add_test(tc_init, test_libvmi_cache);
    return tc_init;
}

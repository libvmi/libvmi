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
#include <inttypes.h>
#include <pwd.h>
#include <config.h>
#include "../libvmi/libvmi.h"
#include "check_tests.h"


#if ENABLE_SHM_SNAPSHOT == 1
/* test vmi_snapshot_create */
START_TEST (test_libvmi_shm_snapshot_create)
{
    vmi_instance_t vmi = NULL;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME | VMI_INIT_SHM,
                      NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);

    status_t ret = vmi_shm_snapshot_create(vmi);
    vmi_shm_snapshot_destroy(vmi);

    fail_unless(ret == VMI_SUCCESS,
                "vmi_init failed with AUTO | COMPLETE");
    fail_unless(vmi != NULL,
                "vmi_init failed to initialize vmi instance struct");
    vmi_destroy(vmi);
}
END_TEST

/* test vmi_get_dgpma */
// we use vmi_read_pa() to verify vmi_get_dgpma()
START_TEST (test_vmi_get_dgpma)
{
    vmi_instance_t vmi = NULL;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME | VMI_INIT_SHM,
                      NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    vmi_shm_snapshot_create(vmi);

    addr_t pa = 0x1000; // just because vmi_read_page() deny to fetch frame 0.
    size_t count = 4096;
    unsigned long max_size = vmi_get_max_physical_address(vmi);
    void *buf_readpa = malloc(count);
    void *buf_dgpma = NULL;
    for (; pa + count <= max_size; pa += count) {
        size_t read_pa = vmi_read_pa(vmi, pa, buf_readpa, count);
        size_t read_dgpma = vmi_get_dgpma(vmi, pa, &buf_dgpma, count);

        if (read_pa == 0 && read_dgpma == 0) {
            continue;
        }

        fail_unless(read_pa == read_dgpma, "vmi_get_dgpma(0x%"PRIx64
                    ") read size %d dosn't conform to %d of vmi_read_pa()",
                    pa, read_dgpma, read_pa);

        int cmp = memcmp(buf_readpa, buf_dgpma, read_pa);
        fail_unless(0 == cmp, "vmi_get_dgpma(0x%"PRIx64
                    ") contents dosn't conform to vmi_read_pa()", pa);
    }
    free(buf_readpa);

    vmi_shm_snapshot_destroy(vmi);
    vmi_destroy(vmi);
}
END_TEST

#if ENABLE_KVM == 1
/* test vmi_get_dgvma */
// we use vmi_read_va() to verify vmi_get_dgvma()
START_TEST (test_vmi_get_dgvma)
{
    vmi_instance_t vmi = NULL;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME | VMI_INIT_SHM,
                      NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    vmi_shm_snapshot_create(vmi);

    addr_t va = 0x0;
    size_t count = 4096;
    unsigned long max_size = 0xffff;
    void *buf_readva = malloc(count);
    void *buf_dgvma = NULL;
    for (; va + count <= max_size; va += count) {
        size_t read_va = vmi_read_va(vmi, va, 0, buf_readva, count);
        size_t read_dgvma = vmi_get_dgvma(vmi, va, 0, &buf_dgvma, count);
        fail_unless(read_va == read_dgvma, "vmi_get_dgvma(0x%"PRIx64
                    ") read size %d dosn't conform to %d of vmi_read_va()",
                    va, read_dgvma, read_va);

        int cmp = memcmp(buf_readva, buf_dgvma, read_va);
        fail_unless(0 == cmp, "vmi_get_dgvma(0x%"PRIx64
                    ") contents dosn't conform to vmi_read_va()", va);
    }
    free(buf_readva);

    vmi_shm_snapshot_destroy(vmi);
    vmi_destroy(vmi);
}
END_TEST
#endif

#endif

/* snapshot test cases */
TCase *shm_snapshot_tcase (void)
{
    TCase *tc_init = tcase_create("LibVMI shm-snapshot");
#if ENABLE_SHM_SNAPSHOT == 1
    tcase_add_test(tc_init, test_libvmi_shm_snapshot_create);
    tcase_add_test(tc_init, test_vmi_get_dgpma);
#if ENABLE_KVM == 1
    tcase_add_test(tc_init, test_vmi_get_dgvma);
#endif
#endif
    return tc_init;
}

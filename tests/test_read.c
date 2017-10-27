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
#include <check.h>
#include "../libvmi/libvmi.h"
#include "check_tests.h"

char *get_sym (vmi_instance_t vmi)
{
    char *sym = NULL;
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
        sym = "init_task";
    } else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {
        sym = "PsInitialSystemProcess";
    }
    return sym;
}

addr_t get_vaddr (vmi_instance_t vmi)
{
    addr_t vaddr = 0;
    char *sym = get_sym(vmi);
    vmi_translate_ksym2v(vmi, sym, &vaddr);
    return vaddr;
}

addr_t get_paddr (vmi_instance_t vmi)
{
    addr_t va = get_vaddr(vmi), pa = 0;
    vmi_translate_kv2p(vmi, va, &pa);
    return pa;
}

START_TEST (test_vmi_read_ksym)
{
    vmi_instance_t vmi = NULL;
    char *sym = NULL;
    char *buf = malloc(100);
    size_t count = 100;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    sym = get_sym(vmi);
    status_t rc = vmi_read_ksym(vmi, sym, count, buf, NULL);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_ksym failed");
    free(buf);
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_va)
{
    vmi_instance_t vmi = NULL;
    addr_t va = 0;
    char *buf = malloc(100);
    size_t count = 100;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    va = get_vaddr(vmi);
    status_t rc = vmi_read_va(vmi, va, 0, count, buf, NULL);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_va failed");
    free(buf);
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_pa)
{
    vmi_instance_t vmi = NULL;
    addr_t pa = 0;
    char *buf = malloc(100);
    size_t count = 100;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    pa = get_paddr(vmi);
    status_t rc = vmi_read_pa(vmi, pa, count, buf, NULL);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_pa failed");
    free(buf);
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_8_ksym)
{
    vmi_instance_t vmi = NULL;
    char *sym = NULL;
    status_t rc = VMI_FAILURE;
    uint8_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    sym = get_sym(vmi);
    rc = vmi_read_8_ksym(vmi, sym, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_8_ksym failed");
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_16_ksym)
{
    vmi_instance_t vmi = NULL;
    char *sym = NULL;
    status_t rc = VMI_FAILURE;
    uint16_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    sym = get_sym(vmi);
    rc = vmi_read_16_ksym(vmi, sym, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_16_ksym failed");
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_32_ksym)
{
    vmi_instance_t vmi = NULL;
    char *sym = NULL;
    status_t rc = VMI_FAILURE;
    uint32_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    sym = get_sym(vmi);
    rc = vmi_read_32_ksym(vmi, sym, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_32_ksym failed");
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_64_ksym)
{
    vmi_instance_t vmi = NULL;
    char *sym = NULL;
    status_t rc = VMI_FAILURE;
    uint64_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    sym = get_sym(vmi);
    rc = vmi_read_64_ksym(vmi, sym, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_64_ksym failed");
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_8_va)
{
    vmi_instance_t vmi = NULL;
    addr_t va = 0;
    status_t rc = VMI_FAILURE;
    uint8_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    va = get_vaddr(vmi);
    rc = vmi_read_8_va(vmi, va, 0, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_8_va failed");
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_16_va)
{
    vmi_instance_t vmi = NULL;
    addr_t va = 0;
    status_t rc = VMI_FAILURE;
    uint16_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    va = get_vaddr(vmi);
    rc = vmi_read_16_va(vmi, va, 0, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_16_va failed");
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_32_va)
{
    vmi_instance_t vmi = NULL;
    addr_t va = 0;
    status_t rc = VMI_FAILURE;
    uint32_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    va = get_vaddr(vmi);
    rc = vmi_read_32_va(vmi, va, 0, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_32_va failed");
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_64_va)
{
    vmi_instance_t vmi = NULL;
    addr_t va = 0;
    status_t rc = VMI_FAILURE;
    uint64_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    va = get_vaddr(vmi);
    rc = vmi_read_64_va(vmi, va, 0, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_64_va failed");
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_8_pa)
{
    vmi_instance_t vmi = NULL;
    addr_t pa = 0;
    status_t rc = VMI_FAILURE;
    uint8_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    pa = get_paddr(vmi);
    rc = vmi_read_8_pa(vmi, pa, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_8_pa failed");
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_16_pa)
{
    vmi_instance_t vmi = NULL;
    addr_t pa = 0;
    status_t rc = VMI_FAILURE;
    uint16_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    pa = get_paddr(vmi);
    rc = vmi_read_16_pa(vmi, pa, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_16_pa failed");
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_32_pa)
{
    vmi_instance_t vmi = NULL;
    addr_t pa = 0;
    status_t rc = VMI_FAILURE;
    uint32_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    pa = get_paddr(vmi);
    rc = vmi_read_32_pa(vmi, pa, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_32_pa failed");
    vmi_destroy(vmi);
}
END_TEST

START_TEST (test_vmi_read_64_pa)
{
    vmi_instance_t vmi = NULL;
    addr_t pa = 0;
    status_t rc = VMI_FAILURE;
    uint64_t value = 0;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    pa = get_paddr(vmi);
    rc = vmi_read_64_pa(vmi, pa, &value);
    fail_unless(VMI_SUCCESS == rc, "vmi_read_64_pa failed");
    vmi_destroy(vmi);
}
END_TEST

/* read test cases */
TCase *read_tcase (void)
{
    TCase *tc_read = tcase_create("LibVMI Read");
    tcase_add_test(tc_read, test_vmi_read_ksym);
    tcase_add_test(tc_read, test_vmi_read_va);
    tcase_add_test(tc_read, test_vmi_read_pa);

    tcase_add_test(tc_read, test_vmi_read_8_ksym);
    tcase_add_test(tc_read, test_vmi_read_16_ksym);
    tcase_add_test(tc_read, test_vmi_read_32_ksym);
    tcase_add_test(tc_read, test_vmi_read_64_ksym);
    // vmi_read_addr_ksym
    // vmi_read_str_ksym

    tcase_add_test(tc_read, test_vmi_read_8_va);
    tcase_add_test(tc_read, test_vmi_read_16_va);
    tcase_add_test(tc_read, test_vmi_read_32_va);
    tcase_add_test(tc_read, test_vmi_read_64_va);
    // vmi_read_addr_va
    // vmi_read_str_va
    // vmi_read_unicode_str_va
    // vmi_convert_str_encoding
    // vmi_free_unicode_str

    tcase_add_test(tc_read, test_vmi_read_8_pa);
    tcase_add_test(tc_read, test_vmi_read_16_pa);
    tcase_add_test(tc_read, test_vmi_read_32_pa);
    tcase_add_test(tc_read, test_vmi_read_64_pa);
    // vmi_read_addr_pa
    // vmi_read_str_pa

    return tc_read;
}

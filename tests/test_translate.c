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
#include <libvmi/libvmi.h>
#include "check_tests.h"


/* test vmi_pid_to_dtb */
START_TEST (test_libvmi_piddtb)
{
    vmi_instance_t vmi = NULL;
    addr_t next_process = 0, list_head = 0;
    addr_t tasks_offset = 0, pid_offset = 0, name_offset = 0;
    int failed = 1;
    os_t os;

    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);

    os = vmi_get_ostype(vmi);

    switch (os) {
        case VMI_OS_LINUX: {
            vmi_get_offset(vmi, "linux_tasks", &tasks_offset);
            vmi_get_offset(vmi, "linux_name", &name_offset);
            vmi_get_offset(vmi, "linux_pid", &pid_offset);

            addr_t init_task_va;
            vmi_translate_ksym2v(vmi, "init_task", &init_task_va);
            vmi_read_addr_va(vmi, init_task_va + tasks_offset, 0, &next_process);
            break;
        }
        case VMI_OS_WINDOWS:
            vmi_get_offset(vmi, "win_tasks", &tasks_offset);
            vmi_get_offset(vmi, "win_pname", &name_offset);
            vmi_get_offset(vmi, "win_pid", &pid_offset);

            vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &list_head);
            vmi_read_addr_va(vmi, list_head + tasks_offset, 0, &next_process);
            break;
        case VMI_OS_FREEBSD:
            vmi_get_offset(vmi, "freebsd_name", &name_offset);
            vmi_get_offset(vmi, "freebsd_pid", &pid_offset);

            vmi_read_addr_ksym(vmi, "allproc", &list_head);
            vmi_read_addr_va(vmi, list_head + tasks_offset, 0, &next_process);
            break;
        default:
            goto done;
    }

    list_head = next_process;
    while (1) {
        vmi_pid_t pid = 0;
        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_process, 0, &tmp_next);
        if (list_head == tmp_next) {
            break;
        }
        vmi_read_32_va(vmi, next_process + pid_offset - tasks_offset, 0, (uint32_t*)&pid);
        if (VMI_OS_WINDOWS != os || pid > 0) {
            addr_t dtb = 0;
            vmi_pid_to_dtb(vmi, pid, &dtb);
            if (dtb) {
                failed = 0;
                break;
            }
        }
        next_process = tmp_next;
    }

done:
    vmi_destroy(vmi);
    fail_unless(!failed, "pid_to_dtb failed");
}
END_TEST


START_TEST (test_libvmi_invalid_pid)
{
    vmi_instance_t vmi = NULL;
    status_t rc = VMI_FAILURE;
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = 0x8000000,
        .pid = 0xfeedbeef,
        .ksym = NULL,
    };
    uint8_t buffer[8];

    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);

    rc = vmi_read(vmi, &ctx, sizeof(buffer), &buffer, NULL);

    vmi_destroy(vmi);
    fail_unless(VMI_FAILURE == rc, "invalid pid accepted");
}
END_TEST


/* test vmi_translate_kv2p */
START_TEST (test_libvmi_kv2p)
{
    vmi_instance_t vmi = NULL;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);

    addr_t va = 0, pa = 0;
    os_t os = vmi_get_ostype(vmi);
    switch (os) {
        case VMI_OS_WINDOWS:
            vmi_translate_ksym2v(vmi, "PsInitialSystemProcess", &va);
            break;
        case VMI_OS_LINUX:
            vmi_translate_ksym2v(vmi, "init_task", &va);
            break;
        case VMI_OS_FREEBSD:
            vmi_translate_ksym2v(vmi, "allproc", &va);
            break;
        default:
            fail_unless(0, "vmi set to invalid os type");
            break;
    }

    vmi_translate_kv2p(vmi, va, &pa);
    fail_unless(pa != 0, "kv2p translation failed");
    vmi_destroy(vmi);
}
END_TEST

/* test vmi_translate_uv2p */
//TODO figure out how to test this
//START_TEST (test_libvmi_uv2p)
//{
//    vmi_translate_uv2p(vmi, vaddr, pid)
//}
//END_TEST

/* test vmi_translate_ksym2v */
START_TEST (test_libvmi_ksym2v)
{
    vmi_instance_t vmi = NULL;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);

    addr_t va = 0;
    os_t os = vmi_get_ostype(vmi);
    switch (os) {
        case VMI_OS_WINDOWS:
            vmi_translate_ksym2v(vmi, "PsInitialSystemProcess", &va);
            break;
        case VMI_OS_LINUX:
            vmi_translate_ksym2v(vmi, "init_task", &va);
            break;
        case VMI_OS_FREEBSD:
            vmi_translate_ksym2v(vmi, "allproc", &va);
            break;
        default:
            break;
    }

    fail_unless(va != 0, "ksym2v translation failed");
    vmi_destroy(vmi);
}
END_TEST

/* translate test cases */
TCase *translate_tcase (void)
{
    TCase *tc_translate = tcase_create("LibVMI Translate");
    tcase_set_timeout(tc_translate, 30);
    tcase_add_test(tc_translate, test_libvmi_ksym2v);
    // uv2p
    tcase_add_test(tc_translate, test_libvmi_kv2p);
    tcase_add_test(tc_translate, test_libvmi_piddtb);
    tcase_add_test(tc_translate, test_libvmi_invalid_pid);
    return tc_translate;
}

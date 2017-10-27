/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
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
#include "../libvmi/libvmi_extra.h"
#include "check_tests.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <glib.h>

/* In this test we force Windows to fully initialize using the KDBG scan
 * which uses get_va_pages internally. */
START_TEST (test_get_va_pages)
{
    vmi_instance_t vmi = NULL;
    vmi_init_complete(&vmi, (void*)get_testvm(), VMI_INIT_DOMAINNAME, NULL,
                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL);
    GHashTable *config = NULL;

    if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {
        addr_t dtb = 0;
        vmi_pid_to_dtb(vmi, 4, &dtb);
        GSList *list = vmi_get_va_pages(vmi, dtb);
        fail_unless(list != NULL, "vmi_get_va_pages failed");
        GSList *loop = list;
        while (loop) {
            free(loop->data);
            loop=loop->next;
        }
        g_slist_free(list);
    }

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);
}
END_TEST

/* translate test cases */
TCase *get_va_pages_tcase (void)
{
    TCase *tc_get_va_pages = tcase_create("LibVMI get_va_pages");
    tcase_set_timeout(tc_get_va_pages, 90);
    tcase_add_test(tc_get_va_pages, test_get_va_pages);
    return tc_get_va_pages;
}


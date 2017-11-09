/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
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
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>

#include <libvmi/libvmi.h>

int
main(
    int argc,
    char **argv)
{
    vmi_instance_t vmi;
    addr_t next_module, list_head;

    if ( argc != 2 )
        return 1;

    /* this is the VM or file that we are looking at */
    char *name = argv[1];

    /* initialize the libvmi library */
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME, NULL,
                              VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    /* pause the vm for consistent memory access */
    vmi_pause_vm(vmi);

    switch (vmi_get_ostype(vmi)) {
        case VMI_OS_LINUX:
            vmi_read_addr_ksym(vmi, "modules", &next_module);
            break;
        case VMI_OS_WINDOWS:
            vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &next_module);
            break;
        default:
            goto error_exit;
    }

    list_head = next_module;

    /* walk the module list */
    while (1) {

        /* follow the next pointer */
        addr_t tmp_next = 0;

        vmi_read_addr_va(vmi, next_module, 0, &tmp_next);

        /* if we are back at the list head, we are done */
        if (list_head == tmp_next) {
            break;
        }

        /* print out the module name */

        /* Note: the module struct that we are looking at has a string
         * directly following the next / prev pointers.  This is why you
         * can just add the length of 2 address fields to get the name.
         * See include/linux/module.h for mode details */
        if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
            char *modname = NULL;

            if (VMI_PM_IA32E == vmi_get_page_mode(vmi, 0)) {   // 64-bit paging
                modname = vmi_read_str_va(vmi, next_module + 16, 0);
            } else {
                modname = vmi_read_str_va(vmi, next_module + 8, 0);
            }
            printf("%s\n", modname);
            free(modname);
        } else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {

            unicode_string_t *us = NULL;

            /*
             * The offset 0x58 and 0x2c is the offset in the _LDR_DATA_TABLE_ENTRY structure
             * to the BaseDllName member.
             * These offset values are stable (at least) between XP and Windows 7.
             */

            if (VMI_PM_IA32E == vmi_get_page_mode(vmi, 0)) {
                us = vmi_read_unicode_str_va(vmi, next_module + 0x58, 0);
            } else {
                us = vmi_read_unicode_str_va(vmi, next_module + 0x2c, 0);
            }

            unicode_string_t out = { 0 };
            //         both of these work
            if (us &&
                    VMI_SUCCESS == vmi_convert_str_encoding(us, &out,
                            "UTF-8")) {
                printf("%s\n", out.contents);
                //            if (us &&
                //                VMI_SUCCESS == vmi_convert_string_encoding (us, &out, "WCHAR_T")) {
                //                printf ("%ls\n", out.contents);
                free(out.contents);
            }   // if
            if (us)
                vmi_free_unicode_str(us);
        }
        next_module = tmp_next;
    }

error_exit:
    /* resume the vm */
    vmi_resume_vm(vmi);

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    return 0;
}

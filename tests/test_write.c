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


/* write test cases */
TCase *write_tcase (void)
{
    TCase *tc_write = tcase_create("LibVMI Write");

    // vmi_write_ksym
    // vmi_write_va
    // vmi_write_pa

    // vmi_write_8_ksym
    // vmi_write_16_ksym
    // vmi_write_32_ksym
    // vmi_write_64_ksym

    // vmi_write_8_va
    // vmi_write_16_va
    // vmi_write_32_va
    // vmi_write_64_va

    // vmi_write_8_pa
    // vmi_write_16_pa
    // vmi_write_32_pa
    // vmi_write_64_pa

    return tc_write;
}

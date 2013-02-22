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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>

#include "libvmi.h"
#include "peparse.h"

status_t
is_WINDOWS_KERNEL(
    vmi_instance_t vmi,
    addr_t base_p,
    uint8_t *pe
) {

    status_t ret = VMI_FAILURE;

    void *optional_pe_header = NULL;
    uint16_t optional_header_type = 0;
    struct export_table et;

    peparse_assign_headers(pe, NULL, NULL, &optional_header_type, &optional_pe_header, NULL, NULL);
    addr_t export_header_offset = peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_EXPORT, &optional_header_type, optional_pe_header, NULL, NULL);

    // The kernel's export table is continuously allocated on the PA level with the PE header
    // This trick may not work for other PE headers (though may work for some drivers)
    uint32_t nbytes = vmi_read_pa(vmi, base_p + export_header_offset, &et, sizeof(struct export_table));
    if(nbytes == sizeof(struct export_table) && !(et.export_flags || !et.name) ) {

        char *name = vmi_read_str_pa(vmi, base_p + et.name);

        if(strcmp("ntoskrnl.exe", name)==0)
            ret = VMI_SUCCESS;

        free(name);
    }

    return ret;
}

win_ver_t
find_windows_version2(
    vmi_instance_t vmi,
    addr_t kernel_base_p,
    uint8_t *pe
) {

    uint16_t major_os_version;
    uint16_t minor_os_version;

    uint16_t optional_header_type = 0;
    struct optional_header_pe32 *oh32 = NULL;
    struct optional_header_pe32plus *oh32plus = NULL;

    peparse_assign_headers(pe, NULL, NULL, &optional_header_type, NULL, &oh32, &oh32plus);

    if(optional_header_type == IMAGE_PE32_MAGIC) {
        major_os_version=oh32->major_os_version;
        minor_os_version=oh32->minor_os_version;
    } else
    if(optional_header_type == IMAGE_PE32_PLUS_MAGIC) {
        major_os_version=oh32plus->major_os_version;
        minor_os_version=oh32plus->minor_os_version;
    }

    if(major_os_version == 3) {
        /*if (minor_os_version == 1)
                printf(" Windows NT 3.1");
        if (minor_os_version == 5)
                printf(" Windows NT 3.5");*/
        return VMI_OS_WINDOWS_UNKNOWN;
    } else
    if(major_os_version == 4) {
        //printf(" Windows NT 4.0");
        return VMI_OS_WINDOWS_UNKNOWN;
    } else
    if(major_os_version == 5) {
        if (minor_os_version == 0)
            return VMI_OS_WINDOWS_2000;
        if (minor_os_version == 1)
            return VMI_OS_WINDOWS_XP;
        if (minor_os_version == 2)
            return VMI_OS_WINDOWS_2003;
    } else
    if(major_os_version == 6) {
        if (minor_os_version == 0)
            // Could also be VMI_OS_WINDOWS_2008
            return VMI_OS_WINDOWS_VISTA;
        if (minor_os_version == 1)
            return VMI_OS_WINDOWS_7;
        if (minor_os_version == 2)
            //printf(" Windows 8?");
            return VMI_OS_WINDOWS_UNKNOWN;
    }

    return VMI_OS_WINDOWS_UNKNOWN;
}

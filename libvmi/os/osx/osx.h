/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
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
#ifndef OS_OSX_H_
#define OS_OSX_H_

#include "private.h"

typedef struct osx_segment {
    addr_t mstart;
    addr_t mend;
    addr_t fstart;
    addr_t fend;
    addr_t size;
    char name[16];
} osx_segment_t;


typedef struct mapping {
    osx_segment_t *segments;
    uint32_t count;
    uint32_t slide;     /* ASLR */
    addr_t load_address;

} osx_mapping_t;


typedef struct osx_offsets {
    addr_t pmap;
    addr_t vmspace;
    addr_t p_pid;
    addr_t p_comm;
    // https://github.com/apple-oss-distributions/xnu/blob/aca3beaa3dfbd42498b42c5e5ce20a938e6554e5/osfmk/i386/pmap.h#L583
    addr_t pgd;      /* Kernel+user shared PML4 physical*/
    addr_t pm_ucr3;  /* Mirrored user PML4 physical */
} osx_offsets_t;


struct osx_instance {
    osx_mapping_t k_mmap;
    osx_offsets_t offsets;
    size_t proc_size;
    addr_t _mh_execute_header;
};
typedef struct osx_instance *osx_instance_t;

status_t osx_init(vmi_instance_t instance, GHashTable *config);

status_t osx_get_offset(vmi_instance_t vmi, const char *offset_name, addr_t *offset);

status_t osx_symbol_to_address(vmi_instance_t instance,
                               const char *symbol, addr_t *__unused, addr_t *address);

status_t osx_pid_to_pgd(vmi_instance_t vmi, vmi_pid_t pid, addr_t *pgd);

status_t osx_pgd_to_pid(vmi_instance_t vmi, addr_t pgd, vmi_pid_t *pid);

status_t osx_teardown(vmi_instance_t vmi);

#endif /* OS_OSX_H_ */

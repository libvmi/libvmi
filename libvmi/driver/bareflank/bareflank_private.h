/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * Author: Tamas K Lengyel <lengyelt@ainfosec.com>
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

#ifndef BAREFLANK_PRIVATE_H
#define BAREFLANK_PRIVATE_H

#include <bfhypercall.h>

#define BF_DEBUG(...) dbprint(VMI_DEBUG_BAREFLANK, "--BF: " __VA_ARGS__)
#define BF_PAGE_SIZE 4096

/* GPA remapping helper structs */
typedef struct gpa_flags {
    mv_uint64_t gpa;
    mv_uint64_t flags;
} gpa_flags_t;
typedef struct gpa_remap {
    gpa_flags_t src;
    gpa_flags_t dst;
} gpa_remap_t;

typedef struct bareflank_instance {
    struct mv_handle_t handle;
    char *name;
    uint64_t domainid;
    void *buffer_space;
    GHashTable *remaps;
} bareflank_instance_t;

static inline
bareflank_instance_t *bareflank_get_instance(
    vmi_instance_t vmi)
{
    return ((bareflank_instance_t *) vmi->driver.driver_data);
}

#endif /* BAREFLANK_PRIVATE_H */

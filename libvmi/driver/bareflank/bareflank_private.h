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

#define BF_PAGE_SIZE 4096

typedef struct bareflank_instance {
    char *name;
    uint64_t domainid;
    void *buffer_space;
    GHashTable *remaps;
} bareflank_instance_t;

extern int bareflank_cpuid(uint64_t *rbx, uint64_t *rcx, uint64_t *rdx, void *__placeholder);
extern bool hcall_get_registers(void *buffer, size_t size, uint64_t domainid);
extern bool hcall_v2p(uint64_t va, uint64_t *pa, uint64_t domainid);
extern bool hcall_map_pa(uint64_t va, uint64_t pa, uint64_t domainid);

static inline
bareflank_instance_t *bareflank_get_instance(
    vmi_instance_t vmi)
{
    return ((bareflank_instance_t *) vmi->driver.driver_data);
}

#endif /* BAREFLANK_PRIVATE_H */

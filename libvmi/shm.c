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

#include "private.h"
#include "driver/driver_wrapper.h"

status_t
vmi_shm_snapshot_create(
    vmi_instance_t vmi)
{
    return driver_shm_snapshot_vm(vmi);
}

status_t
vmi_shm_snapshot_destroy(
    vmi_instance_t vmi)
{
    return driver_destroy_shm_snapshot_vm(vmi);
}

size_t
vmi_get_dgpma(
    vmi_instance_t vmi,
    addr_t paddr,
    void **buf_ptr,
    size_t count)
{
    return driver_get_dgpma(vmi, paddr, buf_ptr, count);
}

size_t
vmi_get_dgvma(
    vmi_instance_t vmi,
    addr_t vaddr,
    pid_t pid,
    void **buf_ptr,
    size_t count)
{
    return driver_get_dgvma(vmi, vaddr, pid, buf_ptr, count);
}

#if ENABLE_ADDRESS_CACHE == 1

//
// Virtual address --> Medial address cache implementation

struct v2m_cache_entry {
    addr_t ma;
    uint64_t length;
    addr_t last_used;
};
typedef struct v2m_cache_entry *v2m_cache_entry_t;

static v2m_cache_entry_t v2m_cache_entry_create (vmi_instance_t vmi, addr_t ma, uint64_t length)
{
    v2m_cache_entry_t entry = (v2m_cache_entry_t) g_malloc0(sizeof(struct v2m_cache_entry));
    if ( !entry )
        return NULL;

    ma &= ~((addr_t)vmi->page_size - 1);
    entry->ma = ma;
    entry->length = length;
    entry->last_used = time(NULL);
    return entry;
}

void
v2m_cache_init(
    vmi_instance_t vmi)
{
    vmi->v2m_cache = g_hash_table_new_full((GHashFunc) key_128_hash, key_128_equals, g_free, g_free);
}

void
v2m_cache_destroy(
    vmi_instance_t vmi)
{
    g_hash_table_destroy(vmi->v2m_cache);
}

status_t
v2m_cache_get(
    vmi_instance_t vmi,
    addr_t va,
    pid_t pid,
    addr_t *ma,
    uint64_t *length)
{
    v2m_cache_entry_t entry = NULL;
    struct key_128 local_key;
    key_128_t key = &local_key;

    key_128_init(vmi, key, (uint64_t)va, (uint64_t)pid);

    if ((entry = g_hash_table_lookup(vmi->v2m_cache, key)) != NULL) {

        entry->last_used = time(NULL);
        *ma = entry->ma | ((vmi->page_size - 1) & va);
        *length = entry->length;
        dbprint(VMI_DEBUG_V2MCACHE, "--v2m cache hit 0x%.16"PRIx64" -- 0x%.16"PRIx64" len 0x%.16"PRIx64" (0x%.16"PRIx64"/0x%.16"PRIx64")\n",
                va, *ma, *length, key->high, key->low);
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

void
v2m_cache_set(
    vmi_instance_t vmi,
    addr_t va,
    pid_t pid,
    addr_t ma,
    uint64_t length)
{
    if (!va || !ma) {
        return;
    }
    key_128_t key = key_128_build(vmi, (uint64_t)va, (uint64_t)pid);
    v2m_cache_entry_t entry = v2m_cache_entry_create(vmi, ma, length);
    g_hash_table_insert(vmi->v2m_cache, key, entry);
    dbprint(VMI_DEBUG_V2MCACHE, "--v2m cache set 0x%.16"PRIx64" -- 0x%.16"PRIx64" len 0x%.16"PRIx64" (0x%.16"PRIx64"/0x%.16"PRIx64")\n", va,
            ma, length, key->high, key->low);
}

status_t
v2m_cache_del(
    vmi_instance_t vmi,
    addr_t va,
    pid_t pid)
{
    struct key_128 local_key;
    key_128_t key = &local_key;
    key_128_init(vmi, key, (uint64_t)va, (uint64_t)pid);
    dbprint(VMI_DEBUG_V2MCACHE, "--v2m cache del 0x%.16"PRIx64" (0x%.16"PRIx64"/0x%.16"PRIx64")\n", va,
            key->high, key->low);

    // key collision doesn't really matter here because worst case
    // scenario we incur an small performance hit

    if (TRUE == g_hash_table_remove(vmi->v2m_cache, key)) {
        return VMI_SUCCESS;
    } else {
        return VMI_FAILURE;
    }
}

void
v2m_cache_flush(
    vmi_instance_t vmi)
{
    g_hash_table_remove_all(vmi->v2m_cache);
    dbprint(VMI_DEBUG_V2MCACHE, "--v2m cache flushed\n");
}

#endif

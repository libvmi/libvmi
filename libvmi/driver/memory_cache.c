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

#define _GNU_SOURCE
#include <glib.h>
#include <time.h>

#include "private.h"
#include "glib_compat.h"

struct memory_cache_entry {
    vmi_instance_t vmi;
    addr_t paddr;
    uint32_t length;
    time_t last_updated;
    time_t last_used;
    void *data;
};
typedef struct memory_cache_entry *memory_cache_entry_t;

static inline
void *get_memory_data(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    return vmi->get_data_callback(vmi, paddr, length);
}

#if ENABLE_PAGE_CACHE == 1
//---------------------------------------------------------
// Internal implementation functions

static void
memory_cache_entry_free(
    gpointer data)
{
    memory_cache_entry_t entry = (memory_cache_entry_t) data;

    if (entry) {
        entry->vmi->release_data_callback(entry->data, entry->length);
        free(entry);
    }
}

static void
clean_cache(
    vmi_instance_t vmi)
{
    while (g_queue_get_length(vmi->memory_cache_lru) > vmi->memory_cache_size_max / 2) {
        gint64 *paddr = g_queue_pop_tail(vmi->memory_cache_lru);

        g_hash_table_remove(vmi->memory_cache, paddr);
        g_free(paddr);
    }

    dbprint(VMI_DEBUG_MEMCACHE, "--MEMORY cache cleanup round complete (cache size = %u)\n",
            g_hash_table_size(vmi->memory_cache));
}

static void *
validate_and_return_data(
    vmi_instance_t vmi,
    memory_cache_entry_t entry)
{
    time_t now = time(NULL);

    if (vmi->memory_cache_age &&
            (now - entry->last_updated > vmi->memory_cache_age)) {
        dbprint(VMI_DEBUG_MEMCACHE, "--MEMORY cache refresh 0x%"PRIx64"\n", entry->paddr);
        vmi->release_data_callback(entry->data, entry->length);
        entry->data = get_memory_data(vmi, entry->paddr, entry->length);
        entry->last_updated = now;

        GList* lru_entry = g_queue_find_custom(vmi->memory_cache_lru,
                                               &entry->paddr, g_int64_equal);
        g_queue_unlink(vmi->memory_cache_lru,
                       lru_entry);
        g_queue_push_head_link(vmi->memory_cache_lru, lru_entry);
    }
    entry->last_used = now;
    return entry->data;
}

static memory_cache_entry_t create_new_entry (vmi_instance_t vmi, addr_t paddr,
        uint32_t length)
{

    // sanity check - are we getting memory outside of the physical memory range?
    //
    // This does not work with a Xen PV VM during page table lookups, because
    // cr3 > [physical memory size]. It *might* not work when examining a PV
    // snapshot, since we're not sure where the page tables end up. So, we
    // just do it for a HVM guest.
    //
    // TODO: perform other reasonable checks

    if ((vmi->vm_type == HVM || vmi->vm_type == NORMAL) && (paddr + length > vmi->max_physical_address)) {
        errprint("--requesting PA [0x%"PRIx64"] beyond max physical address [0x%"PRIx64"]\n",
                 paddr + length, vmi->max_physical_address);
        errprint("\tpaddr: %"PRIx64", length %"PRIx32", vmi->max_physical_address %"PRIx64"\n", paddr, length,
                 vmi->max_physical_address);
        return 0;
    }

    memory_cache_entry_t entry =
        (memory_cache_entry_t)
        g_malloc0(sizeof(struct memory_cache_entry));

    if ( !entry )
        return NULL;

    entry->vmi = vmi;
    entry->paddr = paddr;
    entry->length = length;
    entry->last_updated = time(NULL);
    entry->last_used = entry->last_updated;
    entry->data = get_memory_data(vmi, paddr, length);

    return entry;
}

//---------------------------------------------------------
// External API functions
void
memory_cache_init(
    vmi_instance_t vmi,
    void *(*get_data) (vmi_instance_t,
                       addr_t,
                       uint32_t),
    void (*release_data) (void *,
                          size_t),
    unsigned long age_limit)
{
    vmi->memory_cache =
        g_hash_table_new_full(g_int64_hash, g_int64_equal,
                              g_free,
                              memory_cache_entry_free);
    vmi->memory_cache_lru = g_queue_new();
    vmi->memory_cache_age = age_limit;
    vmi->memory_cache_size_max = MAX_PAGE_CACHE_SIZE;
    vmi->get_data_callback = get_data;
    vmi->release_data_callback = release_data;
}

void *
memory_cache_insert(
    vmi_instance_t vmi,
    addr_t paddr)
{
    memory_cache_entry_t entry = NULL;
    addr_t paddr_aligned = paddr & ~(((addr_t) vmi->page_size) - 1);

    if (paddr != paddr_aligned) {
        errprint("Memory cache request for non-aligned page\n");
        return NULL;
    }

    gint64 *key = (gint64*)&paddr;
    if ((entry = g_hash_table_lookup(vmi->memory_cache, key)) != NULL) {
        dbprint(VMI_DEBUG_MEMCACHE, "--MEMORY cache hit 0x%"PRIx64"\n", paddr);
        return validate_and_return_data(vmi, entry);
    } else {
        if (g_queue_get_length(vmi->memory_cache_lru) >= vmi->memory_cache_size_max) {
            clean_cache(vmi);
        }

        dbprint(VMI_DEBUG_MEMCACHE, "--MEMORY cache set 0x%"PRIx64"\n", paddr);

        entry = create_new_entry(vmi, paddr, vmi->page_size);
        if (!entry) {
            errprint("create_new_entry failed\n");
            return 0;
        }

        key = g_malloc0(sizeof(gint64));
        if ( !key ) {
            g_free(entry);
            return 0;
        }

        gint64 *key2 = g_malloc0(sizeof(gint64));
        if ( !key2 ) {
            g_free(entry);
            g_free(key);
            return 0;
        }

        *key = paddr;
        g_hash_table_insert(vmi->memory_cache, key, entry);

        *key2 = paddr;
        g_queue_push_head(vmi->memory_cache_lru, key2);

        return entry->data;
    }
}

void memory_cache_remove(
    vmi_instance_t vmi,
    addr_t paddr)
{
    addr_t paddr_aligned = paddr & ~(((addr_t) vmi->page_size) - 1);

    if (paddr != paddr_aligned) {
        errprint("Memory cache request for non-aligned page\n");
        return;
    }

    gint64 *key = (gint64*)&paddr;

    g_hash_table_remove(vmi->memory_cache, key);
}

void
memory_cache_destroy(
    vmi_instance_t vmi)
{
    vmi->memory_cache_size_max = 0;

    if (vmi->memory_cache_lru) {
        g_queue_foreach(vmi->memory_cache_lru, (GFunc)g_free, NULL);
        g_queue_free(vmi->memory_cache_lru);
        vmi->memory_cache_lru = NULL;
    }

    if (vmi->memory_cache) {
        g_hash_table_destroy(vmi->memory_cache);
        vmi->memory_cache = NULL;
    }

    vmi->memory_cache_age = 0;
    vmi->memory_cache_size_max = 0;
    vmi->get_data_callback = NULL;
    vmi->release_data_callback = NULL;
}

#else
void
memory_cache_init(
    vmi_instance_t vmi,
    void *(*get_data) (vmi_instance_t,
                       addr_t,
                       uint32_t),
    void (*release_data) (void *,
                          size_t),
    unsigned long UNUSED(age_limit))
{
    vmi->get_data_callback = get_data;
    vmi->release_data_callback = release_data;
}

void *
memory_cache_insert(
    vmi_instance_t vmi,
    addr_t paddr)
{
    if (paddr == vmi->last_used_page_key && vmi->last_used_page) {
        return vmi->last_used_page;
    } else {
        if (vmi->last_used_page_key && vmi->last_used_page) {
            vmi->release_data_callback(vmi->last_used_page, vmi->page_size);
        }
        vmi->last_used_page = get_memory_data(vmi, paddr, vmi->page_size);
        vmi->last_used_page_key = paddr;
        return vmi->last_used_page;
    }
}

void memory_cache_remove(
    vmi_instance_t vmi,
    addr_t paddr)
{
    if (paddr == vmi->last_used_page_key && vmi->last_used_page) {
        vmi->release_data_callback(vmi->last_used_page, vmi->page_size);
    }
}

void
memory_cache_destroy(
    vmi_instance_t vmi)
{
    if (vmi->last_used_page_key && vmi->last_used_page) {
        vmi->release_data_callback(vmi->last_used_page, vmi->page_size);
    }
    vmi->last_used_page_key = 0;
    vmi->last_used_page = NULL;
    vmi->get_data_callback = NULL;
    vmi->release_data_callback = NULL;
}
#endif

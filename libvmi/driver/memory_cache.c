/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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

#include "libvmi.h"
#include "private.h"

#define _GNU_SOURCE
#include <glib.h>
#include <time.h>

static GHashTable *ht = NULL;
static unsigned long max_entry_age = 0;
struct memory_cache_entry{
    uint32_t paddr;
    uint32_t length;
    time_t last_updated;
    time_t last_used;
    void *data;
};
typedef struct memory_cache_entry *memory_cache_entry_t;
static void *(*get_data_callback)(vmi_instance_t, uint32_t, uint32_t) = NULL;
static void (*release_data_callback)(void *, size_t) = NULL;

//---------------------------------------------------------
// Internal implementation functions

static void *get_memory_data (vmi_instance_t vmi, uint32_t paddr, uint32_t length)
{
    return get_data_callback(vmi, paddr, length);
}

static void *validate_and_return_data (vmi_instance_t vmi, memory_cache_entry_t entry)
{
    time_t now = time(NULL);
    if (max_entry_age && (now - entry->last_updated > max_entry_age)){
        dbprint("--MEMORY cache refresh 0x%.8x\n", entry->paddr);
		release_data_callback(entry->data, entry->length);
        entry->data = get_memory_data(vmi, entry->paddr, entry->length);
    }
    entry->last_used = now;
    return entry->data;
}

static memory_cache_entry_t create_new_entry (vmi_instance_t vmi, uint32_t paddr, uint32_t length)
{
    memory_cache_entry_t entry =
        (memory_cache_entry_t) safe_malloc(sizeof(struct memory_cache_entry));
    entry->paddr = paddr;
    entry->length = length;
    entry->last_updated = time(NULL);
    entry->last_used = entry->last_updated;
    entry->data = get_memory_data(vmi, paddr, length);
    return entry;
}

//---------------------------------------------------------
// External API functions
void memory_cache_init (
        void *(*get_data)(vmi_instance_t, uint32_t, uint32_t),
		void (*release_data)(void *, size_t),
		unsigned long age_limit)
{
    ht = g_hash_table_new(g_int_hash, g_int_equal);
    max_entry_age = age_limit;
    get_data_callback = get_data;
	release_data_callback = release_data;
}

void *memory_cache_insert (vmi_instance_t vmi, uint32_t paddr, uint32_t *offset)
{
    memory_cache_entry_t entry = NULL;
    *offset = paddr & (vmi->page_size - 1);
    paddr &= ~(vmi->page_size - 1);
    gint key = (gint) paddr;

    if ((entry = g_hash_table_lookup(ht, &key)) != NULL){
        dbprint("--MEMORY cache hit 0x%.8x\n", paddr);
        return validate_and_return_data(vmi, entry);
    }
    else{
        dbprint("--MEMORY cache set 0x%.8x\n", paddr);
        entry = create_new_entry(vmi, paddr, vmi->page_size);
        g_hash_table_insert(ht, &key, entry);
        return entry->data;
    }
}

//TODO should this cache grow indefinately, or should we have a strategy to remove old items?
//TODO if we want to remove old items, perhaps a separate thread so that insert remains fast?
//TODO hash table should be in instance struct and not in a global variable

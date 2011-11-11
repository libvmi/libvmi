/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
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

struct memory_cache_entry{
    addr_t paddr;
    uint32_t length;
    time_t last_updated;
    time_t last_used;
    void *data;
};
typedef struct memory_cache_entry *memory_cache_entry_t;
static void *(*get_data_callback)(vmi_instance_t, addr_t, uint32_t) = NULL;
static void (*release_data_callback)(void *, size_t) = NULL;

//---------------------------------------------------------
// Internal implementation functions

static void *get_memory_data (vmi_instance_t vmi, addr_t paddr, uint32_t length)
{
    return get_data_callback(vmi, paddr, length);
}

static void check_age (gpointer key, gpointer value, gpointer list)
{
    GSList **listptr = (GSList **) list;
    memory_cache_entry_t entry = value;
    time_t now = time(NULL);
    if (now - entry->last_used > 2){
        *listptr = g_slist_prepend(*listptr, key);
        //dbprint("--MEMORY cache cleanup 0x%.16llx\n", entry->paddr);
    }
}

static void list_all (gpointer key, gpointer value, gpointer list)
{
    GSList **listptr = (GSList **) list;
    *listptr = g_slist_prepend(*listptr, key);
}

static void remove_entry (gpointer key, gpointer cache)
{
    memory_cache_entry_t entry = NULL;
    GHashTable *memory_cache = cache;

    if ((entry = g_hash_table_lookup(memory_cache, key)) != NULL){
        release_data_callback(entry->data, entry->length);
        free(entry);
    }
    g_hash_table_remove(memory_cache, key);
}

static void clean_cache (vmi_instance_t vmi)
{
    GSList *list = NULL;
    g_hash_table_foreach(vmi->memory_cache, check_age, &list); // hold items for 2 seconds
    //g_hash_table_foreach(vmi->memory_cache, list_all, &list);  // effectively no cache
    g_slist_foreach(list, remove_entry, vmi->memory_cache);
    g_slist_free(list);
    //dbprint("--MEMORY cache cleanup round complete\n");
}

static void *validate_and_return_data (vmi_instance_t vmi, memory_cache_entry_t entry)
{
    time_t now = time(NULL);
    if (vmi->memory_cache_age && (now - entry->last_updated > vmi->memory_cache_age)){
        //dbprint("--MEMORY cache refresh 0x%.16llx\n", entry->paddr);
		release_data_callback(entry->data, entry->length);
        entry->data = get_memory_data(vmi, entry->paddr, entry->length);
    }
    entry->last_used = now;
    return entry->data;
}

static memory_cache_entry_t create_new_entry (vmi_instance_t vmi, addr_t paddr, uint32_t length)
{
    memory_cache_entry_t entry =
        (memory_cache_entry_t) safe_malloc(sizeof(struct memory_cache_entry));
    entry->paddr = paddr;
    entry->length = length;
    entry->last_updated = time(NULL);
    entry->last_used = entry->last_updated;
    entry->data = get_memory_data(vmi, paddr, length);
    clean_cache(vmi);
    return entry;
}

//---------------------------------------------------------
// External API functions
void memory_cache_init (
        vmi_instance_t vmi,
        void *(*get_data)(vmi_instance_t, addr_t, uint32_t),
		void (*release_data)(void *, size_t),
		unsigned long age_limit)
{
    vmi->memory_cache = g_hash_table_new(g_int_hash, g_int_equal);
    vmi->memory_cache_age = age_limit;
    get_data_callback = get_data;
	release_data_callback = release_data;
}

void *memory_cache_insert (vmi_instance_t vmi, addr_t paddr, uint32_t *offset)
{
    memory_cache_entry_t entry = NULL;
    *offset = (uint32_t) (paddr & (vmi->page_size - 1));
    paddr &= ~( ((addr_t) vmi->page_size) - 1);
    gint key = (gint) paddr;
    //dbprint("--MEMORY cache warning: possible truncation 0x%llx --> 0x%lx\n", paddr, key);

    if ((entry = g_hash_table_lookup(vmi->memory_cache, &key)) != NULL){
        //dbprint("--MEMORY cache hit 0x%.16llx\n", paddr);
        return validate_and_return_data(vmi, entry);
    }
    else{
        //dbprint("--MEMORY cache set 0x%.16llx\n", paddr);
        entry = create_new_entry(vmi, paddr, vmi->page_size);
        g_hash_table_insert(vmi->memory_cache, &key, entry);
        //dbprint("--MEMORY cache memory at 0x%llx\n", entry->data);
        return entry->data;
    }
}

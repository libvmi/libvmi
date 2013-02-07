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

// Three kinds of cache:
//  1) PID --> DTB
//  2) Symbol --> Virtual address
//  3) Virtual address --> physical address

#include "libvmi.h"
#include "private.h"

#define _GNU_SOURCE
#include <glib.h>
#include <time.h>
#include <string.h>

#include "glib_compat.h"

#if ENABLE_ADDRESS_CACHE == 1
//
// PID --> DTB cache implementation
// Note: DTB is a physical address
struct pid_cache_entry {
    int pid;
    addr_t dtb;
    time_t last_used;
};
typedef struct pid_cache_entry *pid_cache_entry_t;

static void
pid_cache_key_free(
    gpointer data)
{
    if (data)
        free(data);
}

static void
pid_cache_entry_free(
    gpointer data)
{
    pid_cache_entry_t entry = (pid_cache_entry_t) data;

    if (entry)
        free(entry);
}

static pid_cache_entry_t
pid_cache_entry_create(
    int pid,
    addr_t dtb)
{
    pid_cache_entry_t entry =
        (pid_cache_entry_t) safe_malloc(sizeof(struct pid_cache_entry));
    entry->pid = pid;
    entry->dtb = dtb;
    entry->last_used = time(NULL);
    return entry;
}

void
pid_cache_init(
    vmi_instance_t vmi)
{
    vmi->pid_cache =
        g_hash_table_new_full(g_int_hash, g_int_equal,
                              pid_cache_key_free, pid_cache_entry_free);
}

void
pid_cache_destroy(
    vmi_instance_t vmi)
{
    g_hash_table_destroy(vmi->pid_cache);
}

status_t
pid_cache_get(
    vmi_instance_t vmi,
    int pid,
    addr_t *dtb)
{
    pid_cache_entry_t entry = NULL;
    gint key = (gint) pid;

    if ((entry = g_hash_table_lookup(vmi->pid_cache, &key)) != NULL) {
        entry->last_used = time(NULL);
        *dtb = entry->dtb;
        dbprint("--PID cache hit %d -- 0x%.16llx\n", pid, *dtb);
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

void
pid_cache_set(
    vmi_instance_t vmi,
    int pid,
    addr_t dtb)
{
    gint *key = (gint *) safe_malloc(sizeof(gint));

    *key = pid;
    pid_cache_entry_t entry = pid_cache_entry_create(pid, dtb);

    g_hash_table_insert(vmi->pid_cache, key, entry);
    dbprint("--PID cache set %d -- 0x%.16llx\n", pid, dtb);
}

status_t
pid_cache_del(
    vmi_instance_t vmi,
    int pid)
{
    gint key = (gint) pid;

    dbprint("--PID cache del %d\n", pid);
    if (TRUE == g_hash_table_remove(vmi->pid_cache, &key)) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

void
pid_cache_flush(
    vmi_instance_t vmi)
{
    g_hash_table_remove_all(vmi->pid_cache);
    dbprint("--PID cache flushed\n");
}

//
// Symbol --> Virtual address cache implementation
struct sym_cache_entry {
    char *sym;
    addr_t va;
    time_t last_used;
};
typedef struct sym_cache_entry *sym_cache_entry_t;

static void
sym_cache_entry_free(
    gpointer data)
{
    sym_cache_entry_t entry = (sym_cache_entry_t) data;

    if (entry) {
        if (entry->sym)
            free(entry->sym);
        free(entry);
    }
}

static sym_cache_entry_t
sym_cache_entry_create(
    char *sym,
    addr_t va)
{
    sym_cache_entry_t entry =
        (sym_cache_entry_t) safe_malloc(sizeof(struct sym_cache_entry));
    entry->sym = strdup(sym);
    entry->va = va;
    entry->last_used = time(NULL);
    return entry;
}

void
sym_cache_init(
    vmi_instance_t vmi)
{
    vmi->sym_cache =
        g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
                              sym_cache_entry_free);
}

void
sym_cache_destroy(
    vmi_instance_t vmi)
{
    g_hash_table_destroy(vmi->sym_cache);
}

status_t
sym_cache_get(
    vmi_instance_t vmi,
    char *sym,
    addr_t *va)
{
    sym_cache_entry_t entry = NULL;

    if ((entry = g_hash_table_lookup(vmi->sym_cache, sym)) != NULL) {
        entry->last_used = time(NULL);
        *va = entry->va;
        dbprint("--SYM cache hit %s -- 0x%.16llx\n", sym, *va);
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

void
sym_cache_set(
    vmi_instance_t vmi,
    char *sym,
    addr_t va)
{
    sym_cache_entry_t entry = sym_cache_entry_create(sym, va);

    g_hash_table_insert(vmi->sym_cache, sym, entry);
    dbprint("--SYM cache set %s -- 0x%.16llx\n", sym, va);
}

status_t
sym_cache_del(
    vmi_instance_t vmi,
    char *sym)
{
    dbprint("--SYM cache del %s\n", sym);
    if (TRUE == g_hash_table_remove(vmi->sym_cache, sym)) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

void
sym_cache_flush(
    vmi_instance_t vmi)
{
    g_hash_table_remove_all(vmi->sym_cache);
    dbprint("--SYM cache flushed\n");
}

struct v2p_cache_key{
    addr_t va;
    addr_t dtb;
};
typedef struct v2p_cache_key *v2p_cache_key_t;


//
// Virtual address --> Physical address cache implementation
struct v2p_cache_entry {
    addr_t pa;
    addr_t last_used;
};
typedef struct v2p_cache_entry *v2p_cache_entry_t;

// This function borrowed from cityhash-1.0.3
static uint64_t
hash128to64(
    uint64_t low,
    uint64_t high)
{
    // Murmur-inspired hashing
    uint64_t kMul = 0x9ddfea08eb382d69ULL;
    uint64_t a = (low ^ high) * kMul;

    a ^= (a >> 47);
    uint64_t b = (high ^ a) * kMul;

    b ^= (b >> 47);
    b *= kMul;
    return b;
}


static v2p_cache_entry_t v2p_cache_entry_create (vmi_instance_t vmi, addr_t pa)
{
    v2p_cache_entry_t entry = (v2p_cache_entry_t) safe_malloc(sizeof(struct v2p_cache_entry));
    pa &= ~((addr_t)vmi->page_size - 1);
    entry->pa = pa;
    entry->last_used = time(NULL);
    return entry;
}


static gint64 v2p_cache_hash(gconstpointer key){
    const v2p_cache_key_t cache_key = key;
    return hash128to64(cache_key->dtb, cache_key->va);
}

static gboolean v2p_cache_equals(gconstpointer key1, gconstpointer key2){
    const v2p_cache_key_t cache_key1 = key1;
    const v2p_cache_key_t cache_key2 = key2;
    return cache_key1->dtb == cache_key2->dtb && cache_key1->va == cache_key2->va;
}

/*
 * Initialize an already allocated cache entry with the given physical address.
 *
 * This is for performance!
 */
static void v2p_cache_key_init(vmi_instance_t vmi, v2p_cache_key_t key, addr_t va, addr_t dtb)
{
    va = (va & ~((addr_t)vmi->page_size - 1));
    key->va = va;
    key->dtb = dtb;
}

static v2p_cache_key_t v2p_build_key (vmi_instance_t vmi, addr_t va, addr_t dtb)
{
    v2p_cache_key_t key = (v2p_cache_key_t) safe_malloc(sizeof(struct v2p_cache_key));
    v2p_cache_key_init(vmi, key, va, dtb);
    return key;
}

void
v2p_cache_init(
    vmi_instance_t vmi)
{
    vmi->v2p_cache = g_hash_table_new_full(v2p_cache_hash, v2p_cache_equals, g_free, g_free);
}

void
v2p_cache_destroy(
    vmi_instance_t vmi)
{
    g_hash_table_destroy(vmi->v2p_cache);
}

status_t
v2p_cache_get(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb,
    addr_t *pa)
{
    v2p_cache_entry_t entry = NULL;
    struct v2p_cache_key local_key;
    v2p_cache_key_t key = &local_key;

    v2p_cache_key_init(vmi, key, va, dtb);

    if ((entry = g_hash_table_lookup(vmi->v2p_cache, key)) != NULL) {

        entry->last_used = time(NULL);
        *pa = entry->pa | ((vmi->page_size - 1) & va);
        dbprint("--V2P cache hit 0x%.16llx -- 0x%.16llx (0x%.16llx/0x%.16llx)\n",
                va, *pa, key->dtb, key->va);
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

void
v2p_cache_set(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb,
    addr_t pa)
{
    if (!va || !dtb || !pa) {
        return;
    }
    v2p_cache_key_t key = v2p_build_key(vmi, va, dtb);
    v2p_cache_entry_t entry = v2p_cache_entry_create(vmi, pa);
    g_hash_table_insert(vmi->v2p_cache, key, entry);
    dbprint("--V2P cache set 0x%.16llx -- 0x%.16llx (0x%.16llx/0x%.16llx)\n", va,
            pa, key->dtb, key->va);
}

status_t
v2p_cache_del(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb)
{
    struct v2p_cache_key local_key;
    v2p_cache_key_t key = &local_key;
    v2p_cache_key_init(vmi, key, va, dtb);
    dbprint("--V2P cache del 0x%.16llx (0x%.16llx/0x%.16llx)\n", va, key->dtb,
            key->va);

    // key collision doesn't really matter here because worst case
    // scenario we incur an small performance hit

    if (TRUE == g_hash_table_remove(vmi->v2p_cache, key)){
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

void
v2p_cache_flush(
    vmi_instance_t vmi)
{
    g_hash_table_remove_all(vmi->v2p_cache);
    dbprint("--V2P cache flushed\n");
}

#else
void
pid_cache_init(
    vmi_instance_t vmi)
{
    return;
}

void
pid_cache_destroy(
    vmi_instance_t vmi)
{
    return;
}

status_t
pid_cache_get(
    vmi_instance_t vmi,
    int pid,
    addr_t *dtb)
{
    return VMI_FAILURE;
}

void
pid_cache_set(
    vmi_instance_t vmi,
    int pid,
    addr_t dtb)
{
    return;
}

status_t
pid_cache_del(
    vmi_instance_t vmi,
    int pid)
{
    return VMI_FAILURE;
}

void
pid_cache_flush(
    vmi_instance_t vmi)
{
    return;
}

void
sym_cache_init(
    vmi_instance_t vmi)
{
    return;
}

void
sym_cache_destroy(
    vmi_instance_t vmi)
{
    return;
}

status_t
sym_cache_get(
    vmi_instance_t vmi,
    char *sym,
    addr_t *va)
{
    return VMI_FAILURE;
}

void
sym_cache_set(
    vmi_instance_t vmi,
    char *sym,
    addr_t va)
{
    return;
}

status_t
sym_cache_del(
    vmi_instance_t vmi,
    char *sym)
{
    return VMI_FAILURE;
}

void
sym_cache_flush(
    vmi_instance_t vmi)
{
    return;
}

void
v2p_cache_init(
    vmi_instance_t vmi)
{
    return;
}

void
v2p_cache_destroy(
    vmi_instance_t vmi)
{
    return;
}

status_t
v2p_cache_get(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb,
    addr_t *pa)
{
    return VMI_FAILURE;
}

void
v2p_cache_set(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb,
    addr_t pa)
{
    return;
}

status_t
v2p_cache_del(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb)
{
    return VMI_FAILURE;
}

void
v2p_cache_flush(
    vmi_instance_t vmi)
{
    return;
}
#endif

// Below are wrapper functions for external API access to the cache
void
vmi_pidcache_add(
    vmi_instance_t vmi,
    int pid,
    addr_t dtb)
{
    return pid_cache_set(vmi, pid, dtb);
}

void
vmi_pidcache_flush(
    vmi_instance_t vmi)
{
    return pid_cache_flush(vmi);
}

void
vmi_symcache_add(
    vmi_instance_t vmi,
    char *sym,
    addr_t va)
{
    return sym_cache_set(vmi, sym, va);
}

void
vmi_symcache_flush(
    vmi_instance_t vmi)
{
    return sym_cache_flush(vmi);
}

void
vmi_v2pcache_add(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb,
    addr_t pa)
{
    return v2p_cache_set(vmi, va, dtb, pa);
}

void
vmi_v2pcache_flush(
    vmi_instance_t vmi)
{
    return v2p_cache_flush(vmi);
}

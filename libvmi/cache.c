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

// Four kinds of cache:
//  1) PID --> DTB
//  2) Symbol --> Virtual address
//  3) Virtual address --> physical address
//  4) Virtual address --> Medial address (for dgvma of shm-snapshot)

#define _GNU_SOURCE
#include <glib.h>
#include <time.h>
#include <string.h>

#include "private.h"
#include "glib_compat.h"

// This function borrowed from cityhash-1.0.3
uint64_t hash128to64(
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

guint64 key_128_hash(gconstpointer key)
{
    const key_128_t cache_key = (const key_128_t) key;
    return hash128to64(cache_key->low, cache_key->high);
}

gboolean key_128_equals(gconstpointer key1, gconstpointer key2)
{
    const key_128_t cache_key1 = (const key_128_t) key1;
    const key_128_t cache_key2 = (const key_128_t) key2;
    return cache_key1->low == cache_key2->low && cache_key1->high == cache_key2->high;
}

/*
 * Initialize an already allocated key with the given values.
 * This is for performance!
 */
void key_128_init(vmi_instance_t vmi, key_128_t key, uint64_t low, uint64_t high)
{
    low = (low & ~((uint64_t)vmi->page_size - 1));
    key->low = low;
    key->high = high;
}

key_128_t key_128_build (vmi_instance_t vmi, uint64_t low, uint64_t high)
{
    key_128_t key = (key_128_t) g_malloc0(sizeof(struct key_128));
    if ( key )
        key_128_init(vmi, key, low, high);
    return key;
}

//
// PID --> DTB cache implementation
// Note: DTB is a physical address
struct pid_cache_entry {
    vmi_pid_t pid;
    addr_t dtb;
};
typedef struct pid_cache_entry *pid_cache_entry_t;

static void
pid_cache_key_free(
    gpointer data)
{
    free(data);
}

static void
pid_cache_entry_free(
    gpointer data)
{
    pid_cache_entry_t entry = (pid_cache_entry_t) data;
    free(entry);
}

static pid_cache_entry_t pid_cache_entry_create(
    vmi_pid_t pid,
    addr_t dtb)
{
    pid_cache_entry_t entry =
        (pid_cache_entry_t) g_malloc0(sizeof(struct pid_cache_entry));

    if ( !entry )
        return NULL;

    entry->pid = pid;
    entry->dtb = dtb;
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
    if ( vmi->pid_cache )
        g_hash_table_destroy(vmi->pid_cache);
}

status_t
pid_cache_get(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t *dtb)
{
    pid_cache_entry_t entry = NULL;
    gint key = (gint) pid;

    if ((entry = g_hash_table_lookup(vmi->pid_cache, &key)) != NULL) {
        *dtb = entry->dtb;
        dbprint(VMI_DEBUG_PIDCACHE, "--PID cache hit %d -- 0x%.16"PRIx64"\n", pid, *dtb);
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

void
pid_cache_set(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t dtb)
{
    gint *key = (gint *) g_malloc0(sizeof(gint));

    if ( !key )
        return;

    *key = pid;
    pid_cache_entry_t entry = pid_cache_entry_create(pid, dtb);

    if ( !entry ) {
        g_free(key);
        return;
    }

    if ( !g_hash_table_insert_compat(vmi->pid_cache, key, entry) ) {
        g_free(key);
        g_free(entry);
    }

    dbprint(VMI_DEBUG_PIDCACHE, "--PID cache set %d -- 0x%.16"PRIx64"\n", pid, dtb);
}

status_t
pid_cache_del(
    vmi_instance_t vmi,
    vmi_pid_t pid)
{
    gint key = (gint) pid;

    dbprint(VMI_DEBUG_PIDCACHE, "--PID cache del %d\n", pid);
    if (TRUE == g_hash_table_remove(vmi->pid_cache, &key)) {
        return VMI_SUCCESS;
    } else {
        return VMI_FAILURE;
    }
}

void
pid_cache_flush(
    vmi_instance_t vmi)
{
    g_hash_table_remove_all(vmi->pid_cache);
    dbprint(VMI_DEBUG_PIDCACHE, "--PID cache flushed\n");
}

//
// Symbol --> Virtual address cache implementation
struct sym_cache_entry {
    char *sym;
    addr_t va;
    addr_t base_addr;
    vmi_pid_t pid;
};
typedef struct sym_cache_entry *sym_cache_entry_t;

static void
sym_cache_entry_free(
    gpointer data)
{
    sym_cache_entry_t entry = (sym_cache_entry_t) data;

    if (entry) {
        free(entry->sym);
        free(entry);
    }
}

static sym_cache_entry_t
sym_cache_entry_create(
    const char *sym,
    addr_t va,
    addr_t base_addr,
    vmi_pid_t pid)
{
    sym_cache_entry_t entry =
        (sym_cache_entry_t) g_malloc0(sizeof(struct sym_cache_entry));

    if ( !entry )
        return NULL;

    entry->sym = strdup(sym);
    entry->va = va;
    entry->base_addr = base_addr;
    entry->pid = pid;
    return entry;
}

void
sym_cache_init(
    vmi_instance_t vmi)
{
    vmi->sym_cache =
        g_hash_table_new_full((GHashFunc)key_128_hash, key_128_equals, g_free,
                              (GDestroyNotify)g_hash_table_destroy);
}

void
sym_cache_destroy(
    vmi_instance_t vmi)
{
    if ( vmi->sym_cache )
        g_hash_table_destroy(vmi->sym_cache);
}

status_t
sym_cache_get(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    const char *sym,
    addr_t *va)
{

    status_t ret=VMI_FAILURE;

    GHashTable *symbol_table = NULL;
    sym_cache_entry_t entry = NULL;

    struct key_128 local_key;
    key_128_t key = &local_key;
    key_128_init(vmi, key, (uint64_t)base_addr, (uint64_t)pid);

    if ((symbol_table = g_hash_table_lookup(vmi->sym_cache, key)) == NULL) {
        return ret;
    }

    if ((entry = g_hash_table_lookup(symbol_table, sym)) != NULL) {
        *va = entry->va;
        dbprint(VMI_DEBUG_SYMCACHE, "--SYM cache hit %u:0x%.16"PRIx64":%s -- 0x%.16"PRIx64"\n", pid, base_addr, sym, *va);
        ret=VMI_SUCCESS;
    }

    return ret;
}

void
sym_cache_set(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    const char *sym,
    addr_t va)
{
    GHashTable *symbol_table = NULL;
    char* sym_dup = NULL;
    bool new_symbol_table = 0;

    key_128_t key = key_128_build(vmi, (uint64_t)base_addr, (uint64_t)pid);
    if ( !key )
        return;

    symbol_table = g_hash_table_lookup(vmi->sym_cache, key);
    if ( !symbol_table ) {
        new_symbol_table = 1;

        symbol_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                             sym_cache_entry_free);
        if ( !symbol_table ) {
            g_free(key);
            return;
        }

        if ( !g_hash_table_insert_compat(vmi->sym_cache, key, symbol_table) ) {
            g_hash_table_destroy(symbol_table);
            g_free(key);
            return;
        }
    }

    sym_cache_entry_t entry = sym_cache_entry_create(sym, va, base_addr, pid);
    if ( !entry ) {
        g_free(key);
        return;
    }

    sym_dup = g_strndup(sym, 100);
    if ( !sym_dup ) {
        g_free(key);
        g_free(entry);
        return;
    }

    if ( !g_hash_table_insert_compat(symbol_table, sym_dup, entry) ) {
        if ( new_symbol_table )
            g_hash_table_remove(vmi->sym_cache, key);

        g_free(key);
        g_free(entry);
        g_free(sym_dup);
        goto done;
    }

    if ( !new_symbol_table )
        g_free(key);

done:
    dbprint(VMI_DEBUG_SYMCACHE, "--SYM cache set %s -- 0x%.16"PRIx64"\n", sym, va);
}

status_t
sym_cache_del(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    char *sym)
{
    status_t ret=VMI_FAILURE;
    GHashTable *symbol_table=NULL;
    struct key_128 local_key;
    key_128_t key = &local_key;
    key_128_init(vmi, key, (uint64_t)base_addr, (uint64_t)pid);

    if ((symbol_table = g_hash_table_lookup(vmi->sym_cache, key)) == NULL) {
        return ret;
    }

    dbprint(VMI_DEBUG_SYMCACHE, "--SYM cache del %u:0x%.16"PRIx64":%s\n", pid, base_addr, sym);

    if (TRUE == g_hash_table_remove(symbol_table, sym)) {
        ret=VMI_SUCCESS;

        if (!g_hash_table_size(symbol_table)) {
            g_hash_table_remove(vmi->sym_cache, key);
        }
    }

    return ret;
}

void
sym_cache_flush(
    vmi_instance_t vmi)
{
    g_hash_table_remove_all(vmi->sym_cache);
    dbprint(VMI_DEBUG_SYMCACHE, "--SYM cache flushed\n");
}

void
rva_cache_init(
    vmi_instance_t vmi)
{
    vmi->rva_cache =
        g_hash_table_new_full((GHashFunc)key_128_hash, key_128_equals, g_free,
                              (GDestroyNotify)g_hash_table_destroy);
}

void
rva_cache_destroy(
    vmi_instance_t vmi)
{
    if ( vmi->rva_cache )
        g_hash_table_destroy(vmi->rva_cache);
}

status_t
rva_cache_get(
    vmi_instance_t vmi,
    addr_t base_addr,
    addr_t dtb,
    addr_t rva,
    char **sym)
{
    status_t ret=VMI_FAILURE;

    GHashTable *rva_table = NULL;
    sym_cache_entry_t entry = NULL;

    struct key_128 local_key;
    key_128_t key = &local_key;
    key_128_init(vmi, key, (uint64_t)base_addr, (uint64_t)dtb);

    if ((rva_table = g_hash_table_lookup(vmi->rva_cache, key)) == NULL) {
        return ret;
    }

    if ((entry = g_hash_table_lookup(rva_table, GUINT_TO_POINTER(rva))) != NULL) {
        *sym = entry->sym;
        dbprint(VMI_DEBUG_RVACACHE, "--RVA cache hit 0x%.16"PRIx64":0x%.16"PRIx64":%s -- 0x%.16"PRIx64"\n",
                dtb, base_addr, *sym, rva);
        ret=VMI_SUCCESS;
    }

    return ret;
}

void
rva_cache_set(
    vmi_instance_t vmi,
    addr_t base_addr,
    addr_t dtb,
    addr_t rva,
    char *sym)
{
    GHashTable *rva_table = NULL;
    sym_cache_entry_t entry = sym_cache_entry_create(sym, rva, base_addr, dtb);

    gboolean new_table;
    key_128_t key = key_128_build(vmi, (uint64_t)base_addr, (uint64_t)dtb);
    if ( !key ) {
        g_free(entry);
        return;
    }

    if ((rva_table = g_hash_table_lookup(vmi->rva_cache, key)) == NULL) {
        new_table = 1;
        rva_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                          sym_cache_entry_free);
        if ( !g_hash_table_insert_compat(vmi->rva_cache, GUINT_TO_POINTER(key), rva_table) ) {
            g_free(key);
            g_free(entry);
            g_hash_table_destroy(rva_table);
            return;
        }
    } else {
        g_free(key);
        g_free(entry);
        return;
    }

    if ( g_hash_table_insert_compat(rva_table, GUINT_TO_POINTER(rva), entry) )
        dbprint(VMI_DEBUG_RVACACHE, "--RVA cache set %s -- 0x%.16"PRIx64"\n", sym, rva);
    else {
        if ( new_table ) g_hash_table_destroy(rva_table);
        g_free(key);
        g_free(entry);
    }
}

status_t
rva_cache_del(
    vmi_instance_t vmi,
    addr_t base_addr,
    addr_t dtb,
    addr_t rva)
{
    status_t ret=VMI_FAILURE;
    GHashTable *rva_table=NULL;
    struct key_128 local_key;
    key_128_t key = &local_key;
    key_128_init(vmi, key, (uint64_t)base_addr, (uint64_t)dtb);

    if ((rva_table = g_hash_table_lookup(vmi->rva_cache, key)) == NULL) {
        return ret;
    }

    dbprint(VMI_DEBUG_RVACACHE, "--RVA cache del 0x%.16"PRIx64":0x%.16"PRIx64":0x%.16"PRIx64"\n",
            dtb, base_addr, rva);

    if (TRUE == g_hash_table_remove(rva_table, GUINT_TO_POINTER(rva))) {
        ret=VMI_SUCCESS;

        if (!g_hash_table_size(rva_table)) {
            g_hash_table_remove(vmi->rva_cache, key);
        }
    }

    return ret;
}

void
rva_cache_flush(
    vmi_instance_t vmi)
{
    g_hash_table_remove_all(vmi->rva_cache);
    dbprint(VMI_DEBUG_RVACACHE, "--RVA cache flushed\n");
}

void
v2p_cache_init(
    vmi_instance_t vmi)
{
    vmi->v2p_cache = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free,
                                           (GDestroyNotify)g_hash_table_destroy);
}

void
v2p_cache_destroy(
    vmi_instance_t vmi)
{
    if ( vmi->v2p_cache )
        g_hash_table_destroy(vmi->v2p_cache);
}

status_t
v2p_cache_get(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb,
    addr_t *pa)
{
    GHashTable *v = g_hash_table_lookup(vmi->v2p_cache, &dtb);

    if (v) {
        addr_t *_pa = g_hash_table_lookup(v, &va);

        if ( _pa ) {
            *pa = *_pa | (VMI_BIT_MASK(0,11) & va);
            dbprint(VMI_DEBUG_V2PCACHE, "--V2P cache hit 0x%.16"PRIx64" -- 0x%.16"PRIx64"\n",
                    va, *pa);
            return VMI_SUCCESS;
        }
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
    if (!va || !dtb || !pa)
        return;

    GHashTable *v = g_hash_table_lookup(vmi->v2p_cache, &dtb);
    bool new_process_space = 0;

    if ( !v ) {
        new_process_space = 1;

        v = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
        if ( !v )
            return;

        addr_t *_dtb = g_memdup(&dtb, sizeof(addr_t));
        if ( !_dtb )
            return;

        if ( !g_hash_table_insert_compat(vmi->v2p_cache, _dtb, v) ) {
            g_free(_dtb);
            g_hash_table_destroy(v);
            return;
        }
    }

    addr_t *_va = g_memdup(&va, sizeof(addr_t));
    if ( !_va )
        return;

    addr_t *_pa = g_malloc0(sizeof(addr_t));
    if ( !_pa ) {
        g_free(_va);
        return;
    }

    *_pa = pa & ~VMI_BIT_MASK(0,11);

    if ( g_hash_table_insert_compat(v, _va, _pa) ) {
        dbprint(VMI_DEBUG_V2PCACHE, "--V2P cache set 0x%.16"PRIx64" -- 0x%.16"PRIx64"\n",
                va, pa);
        return;
    }

    if ( new_process_space )
        g_hash_table_remove(vmi->v2p_cache, &dtb);

    g_free(_pa);
    g_free(_va);
}

status_t
v2p_cache_del(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb)
{
    GHashTable *v = g_hash_table_lookup(vmi->v2p_cache, &dtb);
    if ( v && g_hash_table_remove(v, &va)) {
        if ( !g_hash_table_size(v) )
            g_hash_table_remove(vmi->v2p_cache, &dtb);

        dbprint(VMI_DEBUG_V2PCACHE, "--V2P cache del 0x%.16"PRIx64"\n", va);

        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

void
v2p_cache_flush(
    vmi_instance_t vmi,
    addr_t dtb)
{
    if ( ~0ull == dtb )
        g_hash_table_remove_all(vmi->v2p_cache);
    else {
        GHashTable *v = g_hash_table_lookup(vmi->v2p_cache, &dtb);
        if ( v )
            g_hash_table_remove_all(v);
    }
    dbprint(VMI_DEBUG_V2PCACHE, "--V2P cache flushed\n");
}

// Below are wrapper functions for external API access to the cache
void
vmi_pidcache_add(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t dtb)
{
    if (!vmi)
        return;

    return pid_cache_set(vmi, pid, dtb);
}

void
vmi_pidcache_flush(
    vmi_instance_t vmi)
{
    if (!vmi)
        return;

    return pid_cache_flush(vmi);
}

void
vmi_symcache_add(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    char *sym,
    addr_t va)
{
    if (!vmi)
        return;

    return sym_cache_set(vmi, base_addr, pid, sym, va);
}

void
vmi_symcache_flush(
    vmi_instance_t vmi)
{
    if (!vmi)
        return;

    return sym_cache_flush(vmi);
}

void
vmi_rvacache_add(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    addr_t rva,
    char *sym)
{
    if (!vmi)
        return;

    return rva_cache_set(vmi, base_addr, pid, rva, sym);
}

void
vmi_rvacache_flush(
    vmi_instance_t vmi)
{
    if (!vmi)
        return;

    return rva_cache_flush(vmi);
}

void
vmi_v2pcache_add(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb,
    addr_t pa)
{
    if (!vmi)
        return;

    return v2p_cache_set(vmi, va, dtb, pa);
}

void
vmi_v2pcache_flush(
    vmi_instance_t vmi,
    addr_t dtb)
{
    if (!vmi)
        return;

    return v2p_cache_flush(vmi, dtb);
}

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
//  4) Virtual address --> symbol

#define _GNU_SOURCE
#include <glib.h>
#include <time.h>
#include <string.h>

#include "libvmi.h"
#include "private.h"
#include "glib_compat.h"

#ifdef __clang_analyzer__
#define g_free free
#endif

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

guint key_128_hash(gconstpointer key)
{
    const key_128_t cache_key = (const key_128_t) key;
    const uint64_t hash64 = hash128to64(cache_key->low, cache_key->high);
    return g_int64_hash(&hash64);
}

gboolean key_128_equals(gconstpointer key1, gconstpointer key2)
{
    const key_128_t cache_key1 = (const key_128_t) key1;
    const key_128_t cache_key2 = (const key_128_t) key2;
    return cache_key1->low == cache_key2->low && cache_key1->high == cache_key2->high;
}

static inline
void key_128_init(key_128_t key, uint64_t low, uint64_t high)
{
    key->low = low;
    key->high = high;
}

static inline
key_128_t key_128_build (uint64_t low, uint64_t high)
{
    key_128_t key = (key_128_t) g_malloc(sizeof(struct key_128));
    if ( key )
        key_128_init(key, low, high);
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
    g_free(data);
}

static void
pid_cache_entry_free(
    gpointer data)
{
    pid_cache_entry_t entry = (pid_cache_entry_t) data;
    g_free(entry);
}

static pid_cache_entry_t pid_cache_entry_create(
    vmi_pid_t pid,
    addr_t dtb)
{
    pid_cache_entry_t entry =
        (pid_cache_entry_t) g_malloc(sizeof(struct pid_cache_entry));

    if ( !entry ) {
        return NULL;
    }

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
    pid_cache_entry_t entry = NULL;

    gint *key = (gint *) g_malloc(sizeof(gint));
    if ( !key ) {
        goto cleanup;
    }
    *key = pid;

    entry = pid_cache_entry_create(pid, dtb);
    if ( !entry ) {
        goto cleanup;
    }

    (void) g_hash_table_insert_compat(vmi->pid_cache, key, entry);
    dbprint(VMI_DEBUG_PIDCACHE, "--PID cache set %d -- 0x%.16"PRIx64"\n", pid, dtb);
    return;

cleanup:
    g_free(key);
    g_free(entry);
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
//
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
        g_free(entry->sym);
        g_free(entry);
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
        (sym_cache_entry_t) g_malloc(sizeof(struct sym_cache_entry));

    if ( !entry ) {
        goto cleanup;
    }

    entry->sym = g_strdup(sym);
    if ( !entry->sym ) {
        goto cleanup;
    }

    entry->va = va;
    entry->base_addr = base_addr;
    entry->pid = pid;
    return entry;

cleanup:
    if (entry) {
        g_free(entry->sym);
        g_free(entry);
    }
    return NULL;
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
    key_128_init(key, (uint64_t)base_addr, (uint64_t)pid);

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
    gboolean new_symbol_table = FALSE;
    sym_cache_entry_t entry = NULL;

    key_128_t key = key_128_build((uint64_t)base_addr, (uint64_t)pid);
    if ( !key ) {
        goto cleanup;
    }

    symbol_table = g_hash_table_lookup(vmi->sym_cache, key);
    if ( !symbol_table ) {
        symbol_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                             sym_cache_entry_free);
        if ( !symbol_table ) {
            goto cleanup;
        }
        new_symbol_table = TRUE;

        (void) g_hash_table_insert_compat(vmi->sym_cache, key, symbol_table);
    } else {
        g_free(key);
        key = NULL;
    }

    entry = sym_cache_entry_create(sym, va, base_addr, pid);
    if ( !entry ) {
        goto cleanup;
    }

    sym_dup = g_strndup(sym, 100);
    if ( !sym_dup ) {
        goto cleanup;
    }

    (void) g_hash_table_insert_compat(symbol_table, sym_dup, entry);
    dbprint(VMI_DEBUG_SYMCACHE, "--SYM cache set %s -- 0x%.16"PRIx64"\n", sym, va);
    return;

cleanup:
    g_free(sym_dup);
    g_free(entry);

    if ( new_symbol_table ) {
        // destroys key and value
        g_hash_table_remove(vmi->sym_cache, key);
        key = NULL;
        symbol_table = NULL;
    }

    g_free(key);
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
    key_128_init(key, (uint64_t)base_addr, (uint64_t)pid);

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
    key_128_init(key, (uint64_t)base_addr, (uint64_t)dtb);

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
    sym_cache_entry_t entry = NULL;

    key_128_t key = key_128_build((uint64_t)base_addr, (uint64_t)dtb);
    if ( !key ) {
        goto cleanup;
    }

    entry = sym_cache_entry_create(sym, rva, base_addr, dtb);
    if (!entry) {
        goto cleanup;
    }

    // Given the key from the base and dtb, locate the associated second-level hash table
    if ((rva_table = g_hash_table_lookup(vmi->rva_cache, key)) == NULL) {
        rva_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                          sym_cache_entry_free);
        if (!rva_table) {
            goto cleanup;
        }

        // Don't care whether value was previously in the table
        (void) g_hash_table_insert_compat(vmi->rva_cache, GUINT_TO_POINTER(key), rva_table);
    } else {
        g_free(key);
        // No need to clear contents -- we're returning
    }

    // Don't care whether value was previously in the table
    (void) g_hash_table_insert_compat(rva_table, GUINT_TO_POINTER(rva), entry);
    dbprint(VMI_DEBUG_RVACACHE, "--RVA cache set %s -- 0x%.16"PRIx64"\n", sym, rva);
    return;

cleanup:
    // There's no path to this point after successful creation of rva_table
    g_free(entry);
    g_free(key);
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
    key_128_init(key, (uint64_t)base_addr, (uint64_t)dtb);

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
    vmi->v2p_cache = g_hash_table_new_full((GHashFunc)key_128_hash, key_128_equals, g_free,
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
    addr_t pt,
    addr_t npt,
    addr_t *pa)
{
    struct key_128 local_key;
    key_128_t key = &local_key;
    key_128_init(key, pt, npt);

    GHashTable *v = g_hash_table_lookup(vmi->v2p_cache, key);
    if ( !v ) {
        dbprint(VMI_DEBUG_V2PCACHE, "--V2P cache miss (no address space) 0x%.16"PRIx64" 0x%.16"PRIx64"\n", pt, npt);
        return VMI_FAILURE;
    }

    addr_t offset = VMI_BIT_MASK(0,11) & va;
    va = (va >> 12) << 12;

    gpointer _pa = g_hash_table_lookup(v, &va);
    if ( !_pa ) {
        dbprint(VMI_DEBUG_V2PCACHE, "--V2P cache miss (no page) 0x%.16"PRIx64"\n", va);
        return VMI_FAILURE;
    }

    *pa = GPOINTER_TO_SIZE(_pa);
    *pa |= offset;
    dbprint(VMI_DEBUG_V2PCACHE, "--V2P cache hit 0x%.16"PRIx64" -- 0x%.16"PRIx64"\n",
            va | offset, *pa);

    return VMI_SUCCESS;
}

void
v2p_cache_set(
    vmi_instance_t vmi,
    addr_t va,
    addr_t pt,
    addr_t npt,
    addr_t pa)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!va || !pt || !pa)
        return;
#endif

    key_128_t key = key_128_build(pt, npt);
    if ( !key )
        return;

    GHashTable *v = g_hash_table_lookup(vmi->v2p_cache, key);
    gboolean new_process_space = FALSE;
    addr_t * _va = NULL;

    if ( !v ) {
        new_process_space = TRUE;

        v = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
        if ( !v )
            goto cleanup;

        (void) g_hash_table_insert_compat(vmi->v2p_cache, key, v);
    } else {
        g_free(key);
        key = NULL;
    }

    /* bundle the cache entries per page */
    va = (va >> 12) << 12;
    pa = (pa >> 12) << 12;

    _va = g_memdup(&va, sizeof(addr_t));
    if ( !_va )
        goto cleanup;

    (void) g_hash_table_insert_compat(v, _va, GSIZE_TO_POINTER(pa));

    dbprint(VMI_DEBUG_V2PCACHE, "--V2P cache set for page 0x%.16"PRIx64" -- 0x%.16"PRIx64"\n",
            va, pa);
    return;

cleanup:
    if ( new_process_space )
        g_hash_table_remove(vmi->v2p_cache, key);
    g_free(key);
}

status_t
v2p_cache_del(
    vmi_instance_t vmi,
    addr_t va,
    addr_t pt,
    addr_t npt)
{
    struct key_128 local_key;
    key_128_t key = &local_key;
    key_128_init(key, npt, pt);

    GHashTable *v = g_hash_table_lookup(vmi->v2p_cache, key);
    if ( !v )
        return VMI_SUCCESS;

    va = (va >> 12) << 12;
    (void) g_hash_table_remove(v, &va);

    if (!g_hash_table_size(v))
        g_hash_table_remove(vmi->v2p_cache, key);

    dbprint(VMI_DEBUG_V2PCACHE, "--V2P cache del 0x%.16"PRIx64"\n", va);

    return VMI_SUCCESS;
}

void
v2p_cache_flush(
    vmi_instance_t vmi,
    addr_t pt,
    addr_t npt)
{
    if ( ~0ull == pt )
        g_hash_table_remove_all(vmi->v2p_cache);
    else {
        struct key_128 local_key;
        key_128_t key = &local_key;
        key_128_init(key, npt, pt);
        (void) g_hash_table_remove(vmi->v2p_cache, key);
    }
    dbprint(VMI_DEBUG_V2PCACHE, "--V2P cache flushed\n");
}

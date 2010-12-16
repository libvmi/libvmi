/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2007  Bryan D. Payne (bryan@thepaynes.cc)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * --------------------
 * This file contains an implementation of a LRU cache for the
 * memory addresses.  The idea is to avoid page table lookups
 * whenever possible since that is an expensive operation.
 *
 * File: xa_cache.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 *
 * $Id: xa_cache.c 161 2008-12-17 18:54:09Z bdpayne $
 * $Date$
 */
#define _GNU_SOURCE
#include <string.h>
#include <time.h>
#include "xa_private.h"

#define MAX_SYM_LEN 512

int xa_check_cache_sym (xa_instance_t *instance,
                        char *symbol_name,
                        int pid,
                        uint32_t *mach_address)
{
    xa_cache_entry_t current;
    int ret = 0;

    current = instance->cache_head;
    while (current != NULL){
        if ((strncmp(current->symbol_name, symbol_name, MAX_SYM_LEN) == 0) &&
            (current->pid == pid) && (current->mach_address)){
            current->last_used = time(NULL);
            *mach_address = current->mach_address;
            ret = 1;
            xa_dbprint("++Cache hit (%s --> 0x%.8x)\n",
                symbol_name, *mach_address);
            goto exit;
        }
        current = current->next;
    }

exit:
    return ret;
}

int xa_check_cache_virt (xa_instance_t *instance,
                         uint32_t virt_address,
                         int pid,
                         uint32_t *mach_address)
{
    xa_cache_entry_t current;
    int ret = 0;
    uint32_t lookup = virt_address & ~(instance->page_size - 1);

    current = instance->cache_head;
    for (current = instance->cache_head;
         current != NULL;
         current = current->next)
    {
        if (!current->virt_address){
            continue;
        }
        else if ((current->virt_address == lookup) &&
            (current->pid == pid) &&
            (current->mach_address)){
            current->last_used = time(NULL);
            *mach_address = (current->mach_address |
                (virt_address & (instance->page_size - 1)));
            ret = 1;
            xa_dbprint("++Cache hit (0x%.8x --> 0x%.8x, 0x%.8x)\n",
                virt_address, *mach_address, current->mach_address);
            goto exit;
        }
    }

exit:
    return ret;
}

int xa_update_cache (xa_instance_t *instance,
                     char *symbol_name,
                     uint32_t virt_address,
                     int pid,
                     uint32_t mach_address)
{
    xa_cache_entry_t new_entry = NULL;
    uint32_t vlookup = virt_address & ~(instance->page_size - 1);
    uint32_t mlookup = mach_address & ~(instance->page_size - 1);

    /* is cache enabled? */
    if (XA_CACHE_SIZE == 0){
        return 1;
    }

    /* does anything match the passed symbol_name? */
    /* if so, update other entries */
    if (symbol_name){
        xa_cache_entry_t current = instance->cache_head;
        while (current != NULL){
            if (strncmp(current->symbol_name, symbol_name, MAX_SYM_LEN) == 0){
                current->last_used = time(NULL);
                current->virt_address = 0;
                current->pid = pid;
                if (mach_address){
                    current->mach_address = mach_address;
                }
                else{
                    current->mach_address =
                        xa_translate_kv2p(instance, virt_address);
                }
                xa_dbprint("++Cache update (%s --> 0x%.8x)\n",
                    symbol_name, current->mach_address);
                goto exit;
            }
            current = current->next;
        }
    }

    /* does anything match the passed virt_address? */
    /* if so, update other entries */
    if (virt_address){
        xa_cache_entry_t current = instance->cache_head;
        while (current != NULL){
            if (current->virt_address == vlookup){
                current->last_used = time(NULL);
                current->pid = pid;
                current->mach_address = mlookup;
                xa_dbprint("++Cache update (0x%.8x --> 0x%.8x)\n",
                    vlookup, mlookup);
                goto exit;
            }
            current = current->next;
        }
    }

    /* was this a spurious call with bad info? */
    if (!symbol_name && !virt_address){
        goto exit;
    }

    /* do we need to remove anything from the cache? */
    if (instance->current_cache_size >= XA_CACHE_SIZE){
        xa_cache_entry_t oldest = instance->cache_head;
        xa_cache_entry_t current = instance->cache_head;

        /* find the least recently used entry */
        while (current != NULL){
            if (current->last_used < oldest->last_used){
                oldest = current;
            }
            current = current->next;
        }

        /* remove that entry */
        if (NULL == oldest->next && NULL == oldest->prev){  /* only entry */
            instance->cache_head = NULL;
            instance->cache_tail = NULL;
        }
        else if (NULL == oldest->next){  /* last entry */
            instance->cache_tail = oldest->prev;
            oldest->prev->next = NULL;
        }
        else if (NULL == oldest->prev){  /* first entry */
            instance->cache_head = oldest->next;
            oldest->next->prev = NULL;
        }
        else{  /* somewhere in the middle */
            oldest->prev->next = oldest->next;
            oldest->next->prev = oldest->prev;
        }

        /* free up memory */
        if (oldest->symbol_name){
            free(oldest->symbol_name);
        }
        oldest->next = NULL;
        oldest->prev = NULL;
        free(oldest);

        instance->current_cache_size--;
    }

    /* allocate memory for the new cache entry */
    new_entry = (xa_cache_entry_t) malloc(sizeof(struct xa_cache_entry));
    new_entry->last_used = time(NULL);
    if (symbol_name){
        new_entry->symbol_name = strndup(symbol_name, MAX_SYM_LEN);
        new_entry->virt_address = 0;
        if (mach_address){
            new_entry->mach_address = mach_address;
        }
        else{
            new_entry->mach_address =
                xa_translate_kv2p(instance, virt_address);
        }
        xa_dbprint("++Cache set (%s --> 0x%.8x)\n",
            symbol_name, new_entry->mach_address);
    }
    else{
        new_entry->symbol_name = strndup("", MAX_SYM_LEN);
        new_entry->virt_address = vlookup;
        new_entry->mach_address = mlookup;
        xa_dbprint("++Cache set (0x%.8x --> 0x%.8x)\n", vlookup, mlookup);
    }
    new_entry->pid = pid;

    /* add it to the end of the list */
    if (NULL != instance->cache_tail){
        instance->cache_tail->next = new_entry;
    }
    new_entry->prev = instance->cache_tail;
    instance->cache_tail = new_entry;
    if (NULL == instance->cache_head){
        instance->cache_head = new_entry;
    }
    new_entry->next = NULL;
    instance->current_cache_size++;

exit:
    return 1;
}

int xa_destroy_cache (xa_instance_t *instance)
{
    xa_cache_entry_t current = instance->cache_head;
    xa_cache_entry_t tmp = NULL;
    while (current != NULL){
        tmp = current->next;
        free(current);
        current = tmp;
    }

    instance->cache_head = NULL;
    instance->cache_tail = NULL;
    instance->current_cache_size = 0;
    return 0;
}

/* ========================================================= */
/*     Cache implementation for PID to PGD cache below.      */
/* ========================================================= */

xa_pid_cache_entry_t xa_check_pid_cache_helper (
    xa_instance_t *instance, int pid)
{
    xa_pid_cache_entry_t current = instance->pid_cache_head;
    while (current != NULL){
        if (current->pid == pid){
            current->last_used = time(NULL);
            goto exit;
        }
        current = current->next;
    }

exit:
    return current;
}

int xa_check_pid_cache (xa_instance_t *instance, int pid, uint32_t *pgd)
{
    xa_pid_cache_entry_t search;
    int ret = 0;

    /* if found, set ret to 1 and put answer in *pgd */
    search = xa_check_pid_cache_helper(instance, pid);
    if (search != NULL){
        *pgd = search->pgd;
        ret = 1;
        xa_dbprint("++PID Cache hit (%d --> 0x%.8x)\n", pid, *pgd);
    }

exit:
    return ret;
}

int xa_update_pid_cache (xa_instance_t *instance, int pid, uint32_t pgd)
{
    xa_pid_cache_entry_t search = NULL;
    xa_pid_cache_entry_t new_entry = NULL;

    /* is cache enabled? */
    if (XA_PID_CACHE_SIZE == 0){
        return 1;
    }

    /* was this a spurious call with bad info? */
    if (!pid){
        goto exit;
    }

    /* does anything match the passed pid? */
    /* if so, update that entry */
    search = xa_check_pid_cache_helper(instance, pid);
    if (search != NULL){
        search->pgd = pgd;
        xa_dbprint("++PID Cache update (%d --> 0x%.8x)\n", pid, pgd);
        goto exit;
    }

    /* do we need to remove anything from the cache? */
    if (instance->current_pid_cache_size >= XA_PID_CACHE_SIZE){
        xa_pid_cache_entry_t oldest = instance->pid_cache_head;
        xa_pid_cache_entry_t current = instance->pid_cache_head;

        /* find the least recently used entry */
        while (current != NULL){
            if (current->last_used < oldest->last_used){
                oldest = current;
            }
            current = current->next;
        }

        /* remove that entry */
        if (NULL == oldest->next && NULL == oldest->prev){  /* only entry */
            instance->pid_cache_head = NULL;
            instance->pid_cache_tail = NULL;
        }
        else if (NULL == oldest->next){  /* last entry */
            instance->pid_cache_tail = oldest->prev;
            oldest->prev->next = NULL;
        }
        else if (NULL == oldest->prev){  /* first entry */
            instance->pid_cache_head = oldest->next;
            oldest->next->prev = NULL;
        }
        else{  /* somewhere in the middle */
            oldest->prev->next = oldest->next;
            oldest->next->prev = oldest->prev;
        }

        /* free up memory */
        oldest->next = NULL;
        oldest->prev = NULL;
        free(oldest);

        instance->current_pid_cache_size--;
    }

    /* allocate memory for the new cache entry */
    new_entry = (xa_pid_cache_entry_t)malloc(sizeof(struct xa_pid_cache_entry));
    new_entry->last_used = time(NULL);
    new_entry->pid = pid;
    new_entry->pgd = pgd;
    xa_dbprint("++PID Cache set (%d --> 0x%.8x)\n", pid, pgd);

    /* add it to the end of the list */
    if (NULL != instance->pid_cache_tail){
        instance->pid_cache_tail->next = new_entry;
    }
    new_entry->prev = instance->pid_cache_tail;
    instance->pid_cache_tail = new_entry;
    if (NULL == instance->pid_cache_head){
        instance->pid_cache_head = new_entry;
    }
    new_entry->next = NULL;
    instance->current_pid_cache_size++;

exit:
    return 1;
}

int xa_destroy_pid_cache (xa_instance_t *instance)
{
    xa_pid_cache_entry_t current = instance->pid_cache_head;
    xa_pid_cache_entry_t tmp = NULL;
    while (current != NULL){
        tmp = current->next;
        free(current);
        current = tmp;
    }

    instance->pid_cache_head = NULL;
    instance->pid_cache_tail = NULL;
    instance->current_pid_cache_size = 0;
    return 0;
}

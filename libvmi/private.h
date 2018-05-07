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

#ifndef PRIVATE_H
#define PRIVATE_H
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#include "libvmi.h"
#include "libvmi_extra.h"
#include "cache.h"
#include "events.h"
#include "shm.h"
#include "slat.h"
#include "rekall.h"
#include "debug.h"
#include "arch/arch_interface.h"
#include "os/os_interface.h"

/**
 * Internal-only enumeration for various VM types.
 */
typedef enum vm_type {
    NORMAL,
    HVM,
    PV32,
    PV64
} vm_type_t;

#include "driver/driver_interface.h"

/**
 * @brief LibVMI Instance.
 *
 * This struct holds all of the relavent information for an instance of
 * LibVMI.  Each time a new domain is accessed, a new instance must
 * be created using the vmi_init function.  When you are done with an instance,
 * its resources can be freed using the vmi_destroy function.
 */
struct vmi_instance {

    vmi_mode_t mode;        /**< VMI_FILE, VMI_XEN, VMI_KVM */

    driver_interface_t driver; /**< The driver supporting the chosen mode */

    uint32_t init_flags;    /**< init flags (events, shm, etc.) */

    char *image_type;       /**< image type that we are accessing */

    char *image_type_complete;  /**< full path for file images */

    uint32_t page_shift;    /**< page shift for last mapped page */

    uint32_t page_size;     /**< page size for last mapped page */

    addr_t kpgd;            /**< kernel page global directory */

    addr_t init_task;       /**< address of task struct for init */

    union {
        struct {
            bool pse;        /**< true if PSE is enabled */

            bool transition_pages; /**< true if transition-pages are enabled */
        } x86;

        struct {
            int t0sz;           /**< TTBR0 VA size (2^(64-t0sz)) */

            int t1sz;           /**< TTBR1 VA size (2^(64-t1sz)) */

            page_size_t tg0;    /**< TTBR0 granule size: 4KB/16KB/64KB */

            page_size_t tg1;    /**< TTBR1 granule size: 4KB/16KB/64KB */
        } arm64;
    };

    page_mode_t page_mode;  /**< paging mode in use */

    arch_interface_t arch_interface; /**< architecture specific functions */

    uint64_t allocated_ram_size; /**< total size of target's allocated memory */

    addr_t max_physical_address; /**< maximum valid physical memory address + 1 */

    vm_type_t vm_type;      /**< VM type */

    os_t os_type;           /**< type of os: VMI_OS_LINUX, etc */

    os_interface_t os_interface; /**< Guest OS specific functions */

    void* os_data; /**< Guest OS specific data */

    GHashTable *pid_cache;  /**< hash table to hold the PID cache data */

    GHashTable *sym_cache;  /**< hash table to hold the sym cache data */

    GHashTable *rva_cache;  /**< hash table to hold the rva cache data */

    GHashTable *v2p_cache;  /**< hash table to hold the v2p cache data */

#if ENABLE_SHM_SNAPSHOT == 1
    GHashTable *v2m_cache;  /**< hash table to hold the v2m cache data */
#endif

#if ENABLE_PAGE_CACHE == 1
    GHashTable *memory_cache;  /**< hash table for memory cache */

    GQueue *memory_cache_lru;  /**< queue holding the most recently used pages */

    uint32_t memory_cache_age; /**< max age of memory cache entry */

    uint32_t memory_cache_size_max;/**< max size of memory cache */
#else
    void *last_used_page;   /**< the last used page */

    addr_t last_used_page_key; /**< the key (addr) of the last used page */
#endif

    unsigned int num_vcpus; /**< number of VCPUs used by this instance */

    vmi_event_t *guest_requested_event; /**< Handler of guest-requested events */

    vmi_event_t *cpuid_event; /**< Handler of CPUID events */

    vmi_event_t *debug_event; /**< Handler of debug exception events */

    vmi_event_t *privcall_event; /**< Handler of privileged call events */

    vmi_event_t *descriptor_access_event; /**< Handler of discriptor access events */

    vmi_event_t *failed_emulation_event; /**< Handler for failed emulation events */

    GHashTable *interrupt_events; /**< interrupt event to function mapping (key: interrupt) */

    GHashTable *mem_events_on_gfn; /**< mem event to functions mapping (key: physical address) */

    GHashTable *mem_events_generic; /**< mem event to functions mapping (key: access type) */

    GHashTable *reg_events; /**< reg event to functions mapping (key: reg) */

    GHashTable *msr_events; /**< reg event to functions mapping (key: msr index) */

    GHashTable *ss_events; /**< single step event to functions mapping (key: vcpu_id) */

    GSList *step_events; /**< events to be re-registered after single-stepping them */

    uint32_t step_vcpus[MAX_SINGLESTEP_VCPUS]; /**< counter of events on vcpus for which we have internal singlestep enabled */

    gboolean event_callback; /**< flag indicating that libvmi is currently issuing an event callback */

    GHashTable *clear_events; /**< table to save vmi_clear_event requests when event_callback is set */

    gboolean shutting_down; /**< flag indicating that libvmi is shutting down */

    GSList *swap_events; /**< list to save vmi_swap_events requests when event_callback is set */

    void *(*get_data_callback) (vmi_instance_t, addr_t, uint32_t); /**< memory_cache function */

    void (*release_data_callback) (void *, size_t); /**< memory_cache function */
};

/** Event singlestep reregister wrapper */
typedef struct step_and_reg_event_wrapper {
    vmi_event_t *event;
    uint32_t vcpu_id;
    uint64_t steps;
    event_callback_t cb;
} step_and_reg_event_wrapper_t;

/** Event swap wrapper */
typedef struct swap_wrapper {
    vmi_event_t *swap_from;
    vmi_event_t *swap_to;
    vmi_event_free_t free_routine;
} swap_wrapper_t;

/** Windows' UNICODE_STRING structure (x86) */
typedef struct _windows_unicode_string32 {
    uint16_t length;
    uint16_t maximum_length;
    uint32_t pBuffer;   // pointer to string contents
} __attribute__ ((packed))
win32_unicode_string_t;

/** Windows' UNICODE_STRING structure (x64) */
typedef struct _windows_unicode_string64 {
    uint16_t length;
    uint16_t maximum_length;
    uint32_t padding;   // align pBuffer
    uint64_t pBuffer;   // pointer to string contents
} __attribute__ ((packed))
win64_unicode_string_t;

/*----------------------------------------------
 * Misc functions
 */
static inline
addr_t canonical_addr(addr_t va)
{
    return VMI_GET_BIT(va, 47) ? (va | 0xffff000000000000) : va;
}

/*----------------------------------------------
 * convenience.c
 */
#ifndef VMI_DEBUG
#define dbprint(category, format, args...) ((void)0)
#else
void dbprint(
    vmi_debug_flag_t category,
    char *format,
    ...) __attribute__((format(printf,2,3)));
#endif
void errprint(
    char *format,
    ...) __attribute__((format(printf,1,2)));
void warnprint(
    char *format,
    ...) __attribute__((format(printf,1,2)));

#define safe_malloc(size) safe_malloc_ (size, __FILE__, __LINE__)
void *safe_malloc_(
    size_t size,
    char const *file,
    int line);
unsigned long get_reg32(
    reg_t r);
addr_t aligned_addr(
    vmi_instance_t vmi,
    addr_t addr);
int is_addr_aligned(
    vmi_instance_t vmi,
    addr_t addr);

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

#ifdef __GNUC__
#  define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_ ## x
#else
#  define UNUSED_FUNCTION(x) UNUSED_ ## x
#endif

/*-------------------------------------
 * accessors.c
 */
void *vmi_read_page(
    vmi_instance_t vmi,
    addr_t frame_num);

status_t vmi_pagetable_lookup_cache(
    vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    addr_t *paddr);

/*-----------------------------------------
 * memory.c
 */

#define PSR_MODE_BIT 0x10 // set on cpsr iff ARM32

status_t find_page_mode_live(
    vmi_instance_t vmi,
    unsigned long vcpu,
    page_mode_t *out_pm);

/*-----------------------------------------
 * strmatch.c
 */

void *boyer_moore_init(
    unsigned char *x,
    int m);
int boyer_moore2(
    void *bm,
    unsigned char *y,
    int n);
void boyer_moore_fini(
    void *bm);

int boyer_moore(
    unsigned char *x,
    int m,
    unsigned char *y,
    int n);

/*-----------------------------------------
 * performance.c
 */
void timer_start(
);
void timer_stop(
    const char *id);

/*----------------------------------------------
 * events.c
 */
status_t events_init(
    vmi_instance_t vmi);
void events_destroy(
    vmi_instance_t vmi);
gboolean event_entry_free (
    gpointer key,
    gpointer value,
    gpointer data);
status_t swap_events(
    vmi_instance_t vmi,
    vmi_event_t *swap_from,
    vmi_event_t *swap_to,
    vmi_event_free_t free_routine);
gboolean clear_events(
    gpointer key,
    gpointer value,
    gpointer data);
gboolean clear_events_full(
    gpointer key,
    gpointer value,
    gpointer data);

#define ghashtable_foreach(table, iter, key, val) \
        g_hash_table_iter_init(&iter, table); \
        while(g_hash_table_iter_next(&iter,(void**)key,(void**)val))

/*----------------------------------------------
 * os/windows/core.c
 */
addr_t get_ntoskrnl_base(
    vmi_instance_t vmi,
    addr_t page_paddr);

/*----------------------------------------------
 * os/windows/kdbg.c
 */
win_ver_t find_windows_version(
    vmi_instance_t vmi,
    addr_t kdbg);

#endif /* PRIVATE_H */

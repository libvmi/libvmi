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
 * This file contains function headers for items that are not exported
 * outside of the library for public use.  These functions are intended
 * to only be used inside the library.
 *
 * File: xa_private.h
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 *
 * $Id: xa_private.h 200 2009-02-23 21:37:56Z bdpayne $
 * $Date: 2006-11-29 20:38:20 -0500 (Wed, 29 Nov 2006) $
 */
#ifndef XA_PRIVATE_H
#define XA_PRIVATE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#ifdef ENABLE_XEN
#include <xenctrl.h>
#endif /* ENABLE_XEN */
#include "xenaccess.h"

/* Architecture dependent constants */
#define fpp 1024		/* number of xen_pfn_t that fits on one frame */

/* other globals */
#define MAX_ROW_LENGTH 200

/* internal error types */
#define XA_ENONE 0
#define XA_ECRITICAL 1
#define XA_EMINOR 2

/*------------------------------
 * Utility function from xa_util
 */

/**
 * Get the specifid bit from a given register entry.
 *
 * @param[in] reg The register contents to parse (e.g., CR0, CR3, etc)
 * @param[in] bit The number of the bit to check.
 * @param[out] zero if the bit in question is zero, else one
 */
int xa_get_bit (unsigned long reg, int bit);

/**
 * Typical debug print function.  Only produces output when XA_DEBUG is
 * defined (usually in xenaccess.h) at compile time.
 */
#ifndef XA_DEBUG
#define xa_dbprint(format, args...) ((void)0)
#else
void xa_dbprint(char *format, ...);
#endif

/*-------------------------------------
 * Definitions to support the LRU cache
 */
#define XA_CACHE_SIZE 25
#define XA_PID_CACHE_SIZE 5

/**
 * Check if a symbol_name is in the LRU cache.
 *
 * @param[in] instance libxa instance
 * @param[in] symbol_name Name of the requested symbol.
 * @param[in] pid Id of the associated process.
 * @param[out] mach_address Machine address of the symbol.
 */
int xa_check_cache_sym (xa_instance_t *instance,
                        char *symbol_name,
                        int pid,
                        uint32_t *mach_address);

/**
 * Check if a virt_address is in the LRU cache.
 * 
 * @param[in] instance libxa instance
 * @param[in] virt_address Virtual address in space of guest process.
 * @param[in] pid Id of the process.
 * @param[out] mach_address Machine address of the symbol.
 */
int xa_check_cache_virt (xa_instance_t *instance,
                         uint32_t virt_address,
                         int pid,
                         uint32_t *mach_address);

/**
 * Updates cache of guest symbols. Every symbol name has an 
 * associated virtual address (address space of host process),
 * pid and machine address (see memory chapter in Xen developers doc).
 *
 * @param[in] instance libxa instance
 * @param[in] symbol_name Name of the cached symbol
 * @param[in] virt_address Virtual address of the symbol
 * @param[in] pid Id of the process associated with symbol
 * @param[in] mach_address Machine address
 */
int xa_update_cache (xa_instance_t *instance,
                     char *symbol_name,
                     uint32_t virt_address,
                     int pid,
                     uint32_t mach_address);

/**
 * Releases the cache.
 *
 * @param[in] instance libxa instance
 * @return 0 for success. -1 for failure.
 */
int xa_destroy_cache (xa_instance_t *instance);

int xa_check_pid_cache (xa_instance_t *instance, int pid, uint32_t *pgd);
int xa_update_pid_cache (xa_instance_t *instance, int pid, uint32_t pgd);
int xa_destroy_pid_cache (xa_instance_t *instance);

/*--------------------------------------------
 * Print util functions from xa_pretty_print.c
 */

/**
 * Prints out the hex and ascii version of a chunk of bytes. The
 * output is similar to what you would get with 'od -h' with the
 * additional ascii information on the right side of the display.
 *
 * @param[in] data The bytes that will be printed to stdout
 * @param[in] length The length (in bytes) of data
 */
void print_hex (unsigned char *data, int length);

#ifdef ENABLE_XEN
/**
 * Prints out the data in a xc_dominfo_t struct to stdout.
 *
 * @param[in] info The struct to print
 */
void print_dominfo (xc_dominfo_t info);
#endif /* ENABLE_XEN */

/*-----------------------------------------
 * Memory access functions from xa_memory.c
 */

/**
 * Memory maps one page from domU to a local address range.  The
 * memory to be mapped is specified with the machine frame number.
 * This memory must be unmapped manually with munmap.
 *
 * @param[in] instance libxa instance
 * @param[in] prot Desired memory protection (see 'man mmap' for values)
 * @param[in] mfn Machine frame number
 * @return Mapped memory or NULL on error
 */
void *xa_mmap_mfn (xa_instance_t *instance, int prot, unsigned long mfn);

/**
 * Memory maps one page from domU to a local address range.  The
 * memory to be mapped is specified with the page frame number.
 * This memory must be unmapped manually with munmap.
 *
 * @param[in] instance libxa instance
 * @param[in] prot Desired memory protection (see 'man mmap' for values)
 * @param[in] pfn Page frame number
 * @return Mapped memory or NULL on error
 */
void *xa_mmap_pfn (xa_instance_t *instance, int prot, unsigned long pfn);

/**
 * Covert virtual address to machine address via page table lookup.
 *
 * @param[in] instance Handle to xenaccess instance.
 * @param[in] pgd Page directory to use for this lookup.
 * @param[in] virt_address Virtual address to convert.
 *
 * @return Machine address resulting from page table lookup.
 */
uint32_t xa_pagetable_lookup (
            xa_instance_t *instance, uint32_t pgd,
            uint32_t virt_address);

/**
 * Find the address of the page global directory for a given PID
 *
 * @param[in] instance Handle to xenaccess instance.
 * @param[in] pid The process to lookup.
 *
 * @return Address of pgd, or zero if no address could be found.
 */
uint32_t xa_pid_to_pgd (xa_instance_t *instance, int pid);

/**
 * Gets address of a symbol in domU virtual memory. It uses System.map
 * file specified in xenaccess configuration file.
 *
 * @param[in] instance Handle to xenaccess instance (see xa_init).
 * @param[in] symbol Name of the requested symbol.
 * @param[out] address The addres of the symbol in guest memory.
 */
int linux_system_map_symbol_to_address (
        xa_instance_t *instance, char *symbol, uint32_t *address);

/**
 * Gets a memory page where @a symbol is located and sets @a offset
 * of the symbol. The mapping is cached internally. 
 *
 * @param[in] instance Handle to xenaccess instance.
 * @param[in] symbol Name of the requested symbol.
 * @param[out] offset Offset of symbol in returned page.
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 *
 * @return Address of a page where \a symbol resides.
 */
void *linux_access_kernel_symbol (
        xa_instance_t *instance, char *symbol, uint32_t *offset, int prot);

/**
 * Gets name of the kernel for given \a id.
 *
 * @param[in] id Domain id.
 *
 * @return String with the path to domU kernel.
 */
char *xa_get_kernel_name (int id);

/**
 * Finds out whether the domU is HVM (Hardware virtual machine).
 *
 * @param[in] id Domain id.
 *
 * @return 1 if domain is HVM. 0 otherwise.
 */
int xa_ishvm (int id);

/**
 * Get the ntoskrnl base address by doing a backwards search.
 *
 * @param[in] instance Handle to xenaccess instance (see xa_init).
 * @param[out] address The address of ntoskrnl base.
 */
uint32_t get_ntoskrnl_base (xa_instance_t *instance);

/**
 * Gets a memory page where \a symbol is located and sets \a offset
 * of the symbol. The mapping is cached internally.
 *
 * @param[in] instance Handle to xenaccess instance.
 * @param[in] symbol Name of the requested symbol.
 * @param[out] offset Offset of symbol in returned page.
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 *
 * @return Address of a page where \a symbol resides.
 */
void *windows_access_kernel_symbol (
        xa_instance_t *instance, char *symbol, uint32_t *offset, int prot);

int windows_init (xa_instance_t *instance);
int linux_init (xa_instance_t *instance);
int get_symbol_row (FILE *f, char *row, char *symbol, int position);
void *xa_map_file_range (xa_instance_t *instance, int prot, unsigned long pfn);
void *xa_map_page (xa_instance_t *instance, int prot, unsigned long frame_num);
uint32_t windows_find_eprocess (xa_instance_t *instance, char *name);
uint32_t xa_find_kernel_pd (xa_instance_t *instance);
int xa_report_error (xa_instance_t *instance, int error, int error_type);
uint32_t xa_get_domain_id (char *name);
char *linux_predict_sysmap_name (uint32_t id);

int windows_export_to_rva (xa_instance_t *, char *, uint32_t *);
int valid_ntoskrnl_start (xa_instance_t *instance, uint32_t addr);


/** Duplicate function from xc_util that should remain
 *  here until Xen 3.1.2 becomes widely distributed.
 */
#ifdef ENABLE_XEN
#ifndef HAVE_MAP_FOREIGN
void *xc_map_foreign_pages(int xc_handle, uint32_t dom, int prot,
                           const xen_pfn_t *arr, int num);
#endif /* HAVE_MAP_FOREIGN */
#endif /* ENABLE_XEN */

#endif /* XA_PRIVATE_H */

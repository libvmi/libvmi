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

#ifndef PRIVATE_H
#define PRIVATE_H
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include "libvmi.h"

/**
 * @brief LibVMI Instance.
 *
 * This struct holds all of the relavent information for an instance of
 * LibVMI.  Each time a new domain is accessed, a new instance must
 * be created using the vmi_init function.  When you are done with an instance,
 * its resources can be freed using the vmi_destroy function.
 */
struct vmi_instance{
    uint32_t mode;          /**< VMI_FILE, VMI_XEN, VMI_KVM */
    uint32_t flags;         /**< flags passed to init function */
    uint32_t init_mode;     /**< VMI_INIT_PARTIAL or VMI_INIT_COMPLETE */
    char *configstr;        /**< string holding config info */
    char *sysmap;           /**< system map file for domain's running kernel */
    char *image_type;       /**< image type that we are accessing */
    uint32_t page_offset;   /**< page offset for this instance */
    uint32_t page_shift;    /**< page shift for last mapped page */
    uint32_t page_size;     /**< page size for last mapped page */
    addr_t kpgd;            /**< kernel page global directory */
    addr_t init_task;       /**< address of task struct for init */
    os_t os_type;           /**< type of os: VMI_OS_LINUX, etc */
    int pae;                /**< nonzero if PAE is enabled */
    int pse;                /**< nonzero if PSE is enabled */
    int lme;                /**< nonzero if LME is enabled */
    reg_t cr3;              /**< value in the CR3 register */
    page_mode_t page_mode;  /**< paging mode in use */
    uint64_t size;          /**< total size of target's memory */
    union{
        struct linux_instance{
            int tasks_offset;    /**< task_struct->tasks */
            int mm_offset;       /**< task_struct->mm */
            int pid_offset;      /**< task_struct->pid */
            int pgd_offset;      /**< mm_struct->pgd */
        } linux_instance;
        struct windows_instance{
            addr_t ntoskrnl;          /**< base phys address for ntoskrnl image */
            addr_t ntoskrnl_va;       /**< base virt address for ntoskrnl image */
            addr_t kddebugger_data64; /**< kernel virtual address for start of KDDEBUGGER_DATA64 structure */
            addr_t kdversion_block;   /**< kernel virtual address for start of KdVersionBlock structure */
            int tasks_offset;    /**< EPROCESS->ActiveProcessLinks */
            int pdbase_offset;   /**< EPROCESS->Pcb.DirectoryTableBase */
            int pid_offset;      /**< EPROCESS->UniqueProcessId */
            int pname_offset;    /**< EPROCESS->ImageFileName */
            win_ver_t version;   /**< version of Windows */
        } windows_instance;
    } os;
    GHashTable *pid_cache;  /**< hash table to hold the PID cache data */
    GHashTable *sym_cache;  /**< hash table to hold the sym cache data */
    GHashTable *v2p_cache;  /**< hash table to hold the v2p cache data */
    void *driver;           /**< driver-specific information */
    GHashTable *memory_cache;       /**< hash table for memory cache */
    uint32_t memory_cache_age; /**< max age of memory cache entry */
};

/** Windows' UNICODE_STRING structure (x86) */
typedef struct _windows_unicode_string32 {
    uint16_t length;
    uint16_t maximum_length;
    uint32_t pBuffer; // pointer to string contents
} __attribute__((packed)) win32_unicode_string_t;

/** Windows' UNICODE_STRING structure (x64) */
typedef struct _windows_unicode_string64 {
    uint16_t length;
    uint16_t maximum_length;
    uint64_t pBuffer; // pointer to string contents
} __attribute__((packed)) win64_unicode_string_t;

/*----------------------------------------------
 * convenience.c
 */
#ifndef VMI_DEBUG
#define dbprint(format, args...) ((void)0)
#else
void dbprint(char *format, ...);
#endif
void errprint (char *format, ...);
void warnprint (char *format, ...);
#define safe_malloc(size) safe_malloc_ (size, __FILE__, __LINE__) 
void *safe_malloc_ (size_t size, char const *file, int line);
unsigned long get_reg32 (reg_t r);
int vmi_get_bit (reg_t reg, int bit);
addr_t p2m (vmi_instance_t vmi, addr_t paddr);
addr_t aligned_addr (vmi_instance_t vmi, addr_t addr);
int is_addr_aligned (vmi_instance_t vmi, addr_t addr);

/*-------------------------------------
 * cache.c
 */
void pid_cache_init (vmi_instance_t vmi);
void pid_cache_destroy (vmi_instance_t vmi);
status_t pid_cache_get (vmi_instance_t vmi, int pid, addr_t *dtb);
void pid_cache_set (vmi_instance_t vmi, int pid, addr_t dtb);
status_t pid_cache_del (vmi_instance_t vmi, int pid);

void sym_cache_init (vmi_instance_t vmi);
void sym_cache_destroy (vmi_instance_t vmi);
status_t sym_cache_get (vmi_instance_t vmi, char *sym, addr_t *va);
void sym_cache_set (vmi_instance_t vmi, char *sym, addr_t va);
status_t sym_cache_del (vmi_instance_t vmi, char *sym);

void v2p_cache_init (vmi_instance_t vmi);
void v2p_cache_destroy (vmi_instance_t vmi);
status_t v2p_cache_get (vmi_instance_t vmi, addr_t va, addr_t dtb, addr_t *pa);
void v2p_cache_set (vmi_instance_t vmi, addr_t va, addr_t dtb, addr_t pa);
status_t v2p_cache_del (vmi_instance_t vmi, addr_t va, addr_t dtb);

/*-----------------------------------------
 * memory.c
 */
addr_t vmi_pid_to_dtb (vmi_instance_t vmi, int pid);
void *vmi_read_page (vmi_instance_t vmi, addr_t frame_num, int is_pfn);

/*-----------------------------------------
 * os/linux/...
 */
status_t linux_init (vmi_instance_t instance);
status_t linux_system_map_symbol_to_address (vmi_instance_t instance, char *symbol, addr_t *address);

/*-----------------------------------------
 * os/windows/...
 */
typedef int(*check_magic_func)(uint32_t);

status_t windows_init (vmi_instance_t instance);
addr_t windows_find_eprocess (vmi_instance_t instance, char *name);
status_t windows_export_to_rva (vmi_instance_t , char *, addr_t *);
status_t windows_kpcr_lookup (vmi_instance_t vmi, char *symbol, addr_t *address);
addr_t windows_find_cr3 (vmi_instance_t vmi);
int find_pname_offset (vmi_instance_t vmi, check_magic_func check);
void find_windows_version (vmi_instance_t vmi);

/*-----------------------------------------
 * read.c
 */
status_t vmi_read_8_ma (vmi_instance_t vmi, addr_t maddr, uint8_t *value);
status_t vmi_read_16_ma (vmi_instance_t vmi, addr_t maddr, uint16_t *value);
status_t vmi_read_32_ma (vmi_instance_t vmi, addr_t maddr, uint32_t *value);
status_t vmi_read_64_ma (vmi_instance_t vmi, addr_t maddr, uint64_t *value);
status_t vmi_read_addr_ma (vmi_instance_t vmi, addr_t maddr, addr_t *value);
char *vmi_read_str_ma (vmi_instance_t vmi, addr_t maddr);

/*-----------------------------------------
 * strmatch.c
 */
int boyer_moore (unsigned char *x, int m, unsigned char *y, int n);

#endif /* PRIVATE_H */

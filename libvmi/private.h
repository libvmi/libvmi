/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#ifndef PRIVATE_H
#define PRIVATE_H
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include "libvmi.h"

/* Architecture dependent constants */
#define fpp 1024		/* number of xen_pfn_t that fits on one frame */

/* other globals */
#define MAX_ROW_LENGTH 200

struct vmi_cache_entry{
    time_t last_used;
    char *symbol_name;
    uint32_t virt_address;
    uint32_t mach_address;
    int pid;
    struct vmi_cache_entry *next;
    struct vmi_cache_entry *prev;
};
typedef struct vmi_cache_entry* vmi_cache_entry_t;

struct vmi_pid_cache_entry{
    time_t last_used;
    int pid;
    uint32_t pgd;
    struct vmi_pid_cache_entry *next;
    struct vmi_pid_cache_entry *prev;
};
typedef struct vmi_pid_cache_entry* vmi_pid_cache_entry_t;

/**
 * @brief LibVMI Instance.
 *
 * This struct holds all of the relavent information for an instance of
 * LibVMI.  Each time a new domain is accessed, a new instance must
 * be created using the vmi_init function.  When you are done with an instance,
 * its resources can be freed using the vmi_destroy function.
 */
struct vmi_instance{
    uint32_t mode;          /**< file or xen VM data source */
    char *sysmap;           /**< system map file for domain's running kernel */
    char *image_type;       /**< image type that we are accessing */
    uint32_t page_offset;   /**< page offset for this instance */
    uint32_t page_shift;    /**< page shift for last mapped page */
    uint32_t page_size;     /**< page size for last mapped page */
    uint32_t kpgd;          /**< kernel page global directory */
    uint32_t init_task;     /**< address of task struct for init */
    os_t os_type;           /**< type of os: VMI_OS_LINUX, etc */
    int pae;                /**< nonzero if PAE is enabled */
    int pse;                /**< nonzero if PSE is enabled */
    uint32_t cr3;           /**< value in the CR3 register */
    unsigned long size;     /**< total size of target's memory */
    vmi_cache_entry_t cache_head;         /**< head of the address cache list */
    vmi_cache_entry_t cache_tail;         /**< tail of the address cache list */
    int current_cache_size;              /**< size of the address cache list */
    vmi_pid_cache_entry_t pid_cache_head; /**< head of the pid cache list */
    vmi_pid_cache_entry_t pid_cache_tail; /**< tail of the pid cache list */
    int current_pid_cache_size;          /**< size of the pid cache list */
    union{
        struct linux_instance{
            int tasks_offset;    /**< task_struct->tasks */
            int mm_offset;       /**< task_struct->mm */
            int pid_offset;      /**< task_struct->pid */
            int pgd_offset;      /**< mm_struct->pgd */
        } linux_instance;
        struct windows_instance{
            uint32_t ntoskrnl;   /**< base phys address for ntoskrnl image */
            uint32_t kddebugger_data64; /**< kernel virtual address for start of KDDEBUGGER_DATA64 structure */
            int tasks_offset;    /**< EPROCESS->ActiveProcessLinks */
            int pdbase_offset;   /**< EPROCESS->Pcb.DirectoryTableBase */
            int pid_offset;      /**< EPROCESS->UniqueProcessId */
        } windows_instance;
    } os;
    void *driver;           /**< driver-specific information */
};

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
int vmi_get_bit (unsigned long reg, int bit);

/*-------------------------------------
 * cache.c
 */
//TODO need to update the cache code and integrate cache lookups back into memory access (we lost them with the access funcs)
#define VMI_CACHE_SIZE 25
#define VMI_PID_CACHE_SIZE 5
int vmi_check_cache_sym (vmi_instance_t instance, char *symbol_name, int pid, uint32_t *mach_address);
int vmi_check_cache_virt (vmi_instance_t instance, uint32_t virt_address, int pid, uint32_t *mach_address);
int vmi_update_cache (vmi_instance_t instance, char *symbol_name, uint32_t virt_address, int pid, uint32_t mach_address);
int vmi_destroy_cache (vmi_instance_t instance);
int vmi_check_pid_cache (vmi_instance_t instance, int pid, uint32_t *pgd);
int vmi_update_pid_cache (vmi_instance_t instance, int pid, uint32_t pgd);
int vmi_destroy_pid_cache (vmi_instance_t instance);

/*-----------------------------------------
 * memory.c
 */
reg_t vmi_pid_to_pgd (vmi_instance_t instance, int pid);
void *vmi_map_page (vmi_instance_t instance, int prot, unsigned long frame_num, int is_pfn);

/*-----------------------------------------
 * os/linux/...
 */
status_t linux_init (vmi_instance_t instance);
status_t linux_system_map_symbol_to_address (vmi_instance_t instance, char *symbol, uint32_t *address);

/*-----------------------------------------
 * os/windows/...
 */
status_t windows_init (vmi_instance_t instance);
uint32_t get_ntoskrnl_base (vmi_instance_t instance);
uint32_t windows_find_eprocess (vmi_instance_t instance, char *name);
status_t windows_export_to_rva (vmi_instance_t , char *, uint32_t *);
status_t valid_ntoskrnl_start (vmi_instance_t instance, uint32_t addr);
status_t windows_kpcr_lookup (vmi_instance_t vmi, char *symbol, uint32_t *address);
uint32_t windows_find_cr3 (vmi_instance_t vmi);

/*-----------------------------------------
 * symbols.c
 */
int get_symbol_row (FILE *f, char *row, char *symbol, int position);

/*-----------------------------------------
 * read.c
 */
status_t vmi_read_8_ma (vmi_instance_t vmi, uint32_t maddr, uint8_t *value);
status_t vmi_read_16_ma (vmi_instance_t vmi, uint32_t maddr, uint16_t *value);
status_t vmi_read_32_ma (vmi_instance_t vmi, uint32_t maddr, uint32_t *value);
status_t vmi_read_64_ma (vmi_instance_t vmi, uint32_t maddr, uint64_t *value);

#endif /* PRIVATE_H */

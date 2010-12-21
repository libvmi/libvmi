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
#include "libvmi.h"

/* Architecture dependent constants */
#define fpp 1024		/* number of xen_pfn_t that fits on one frame */

/* other globals */
#define MAX_ROW_LENGTH 200

/* internal error types */
#define VMI_ENONE 0
#define VMI_ECRITICAL 1
#define VMI_EMINOR 2

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
    uint32_t error_mode;    /**< VMI_FAILHARD or VMI_FAILSOFT */
    char *sysmap;           /**< system map file for domain's running kernel */
    char *image_type;       /**< image type that we are accessing */
    uint32_t page_offset;   /**< page offset for this instance */
    uint32_t page_shift;    /**< page shift for last mapped page */
    uint32_t page_size;     /**< page size for last mapped page */
    uint32_t kpgd;          /**< kernel page global directory */
    uint32_t init_task;     /**< address of task struct for init */
    int os_type;            /**< type of os: VMI_OS_LINUX, etc */
    int hvm;                /**< nonzero if HVM memory image */
    int pae;                /**< nonzero if PAE is enabled */
    int pse;                /**< nonzero if PSE is enabled */
    uint32_t cr3;           /**< value in the CR3 register */
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
            int addr_offset;     /**< mm_struct->start_code */
        } linux_instance;
        struct windows_instance{
            uint32_t ntoskrnl;   /**< base phys address for ntoskrnl image */
            int tasks_offset;    /**< EPROCESS->ActiveProcessLinks */
            int pdbase_offset;   /**< EPROCESS->Pcb.DirectoryTableBase */
            int pid_offset;      /**< EPROCESS->UniqueProcessId */
            int peb_offset;      /**< EPROCESS->Peb */
            int iba_offset;      /**< EPROCESS->Peb.ImageBaseAddress */
            int ph_offset;       /**< EPROCESS->Peb.ProcessHeap */
        } windows_instance;
    } os;
    union{
#ifdef ENABLE_XEN
        struct xen{
            int xc_handle;       /**< handle to xenctrl library (libxc) */
            uint32_t domain_id;  /**< domid that we are accessing */
            int xen_version;     /**< version of Xen libxa is running on */
            xc_dominfo_t info;   /**< libxc info: domid, ssidref, stats, etc */
            uint32_t size;       /**< total size of domain's memory */
            unsigned long *live_pfn_to_mfn_table;
            unsigned long nr_pfns;
        } xen;
#endif
        struct file{
            FILE *fhandle;       /**< handle to the memory image file */
            uint32_t size;       /**< total size of file, in bytes */
        } file;
    } m;
};

/*------------------------------
 * Utility function from vmi_util
 */

/**
 * Get the specifid bit from a given register entry.
 *
 * @param[in] reg The register contents to parse (e.g., CR0, CR3, etc)
 * @param[in] bit The number of the bit to check.
 * @param[out] zero if the bit in question is zero, else one
 */
int vmi_get_bit (unsigned long reg, int bit);

/**
 * Typical debug print function.  Only produces output when VMI_DEBUG is
 * defined (usually in libvmi.h) at compile time.
 */
#ifndef VMI_DEBUG
#define dbprint(format, args...) ((void)0)
#else
void dbprint(char *format, ...);
#endif

/*-------------------------------------
 * Definitions to support the LRU cache
 */
#define VMI_CACHE_SIZE 25
#define VMI_PID_CACHE_SIZE 5

/**
 * Check if a symbol_name is in the LRU cache.
 *
 * @param[in] instance libxa instance
 * @param[in] symbol_name Name of the requested symbol.
 * @param[in] pid Id of the associated process.
 * @param[out] mach_address Machine address of the symbol.
 */
int vmi_check_cache_sym (vmi_instance_t instance,
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
int vmi_check_cache_virt (vmi_instance_t instance,
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
int vmi_update_cache (vmi_instance_t instance,
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
int vmi_destroy_cache (vmi_instance_t instance);

int vmi_check_pid_cache (vmi_instance_t instance, int pid, uint32_t *pgd);
int vmi_update_pid_cache (vmi_instance_t instance, int pid, uint32_t pgd);
int vmi_destroy_pid_cache (vmi_instance_t instance);

/*--------------------------------------------
 * Print util functions from vmi_pretty_print.c
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

/*-----------------------------------------
 * Memory access functions from vmi_memory.c
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
void *vmi_mmap_mfn (vmi_instance_t instance, int prot, unsigned long mfn);

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
void *vmi_mmap_pfn (vmi_instance_t instance, int prot, unsigned long pfn);

/**
 * Covert virtual address to machine address via page table lookup.
 *
 * @param[in] instance Handle to xenaccess instance.
 * @param[in] pgd Page directory to use for this lookup.
 * @param[in] virt_address Virtual address to convert.
 *
 * @return Machine address resulting from page table lookup.
 */
uint32_t vmi_pagetable_lookup (
            vmi_instance_t instance, uint32_t pgd,
            uint32_t virt_address);

/**
 * Find the address of the page global directory for a given PID
 *
 * @param[in] instance Handle to xenaccess instance.
 * @param[in] pid The process to lookup.
 *
 * @return Address of pgd, or zero if no address could be found.
 */
uint32_t vmi_pid_to_pgd (vmi_instance_t instance, int pid);

/**
 * Gets address of a symbol in domU virtual memory. It uses System.map
 * file specified in xenaccess configuration file.
 *
 * @param[in] instance Handle to xenaccess instance (see vmi_init).
 * @param[in] symbol Name of the requested symbol.
 * @param[out] address The addres of the symbol in guest memory.
 */
int linux_system_map_symbol_to_address (
        vmi_instance_t instance, char *symbol, uint32_t *address);

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
        vmi_instance_t instance, char *symbol, uint32_t *offset, int prot);

/**
 * Gets name of the kernel for given \a id.
 *
 * @param[in] id Domain id.
 *
 * @return String with the path to domU kernel.
 */
char *vmi_get_kernel_name (int id);

/**
 * Finds out whether the domU is HVM (Hardware virtual machine).
 *
 * @param[in] id Domain id.
 *
 * @return 1 if domain is HVM. 0 otherwise.
 */
int vmi_ishvm (int id);

/**
 * Get the ntoskrnl base address by doing a backwards search.
 *
 * @param[in] instance Handle to xenaccess instance (see vmi_init).
 * @param[out] address The address of ntoskrnl base.
 */
uint32_t get_ntoskrnl_base (vmi_instance_t instance);

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
        vmi_instance_t instance, char *symbol, uint32_t *offset, int prot);

int windows_init (vmi_instance_t instance);
int linux_init (vmi_instance_t instance);
int get_symbol_row (FILE *f, char *row, char *symbol, int position);
void *vmi_map_file_range (vmi_instance_t instance, int prot, unsigned long pfn);
void *vmi_map_page (vmi_instance_t instance, int prot, unsigned long frame_num);
uint32_t windows_find_eprocess (vmi_instance_t instance, char *name);
uint32_t vmi_find_kernel_pd (vmi_instance_t instance);
int vmi_report_error (vmi_instance_t instance, int error, int error_type);
uint32_t vmi_get_domain_id (char *name);
char *linux_predict_sysmap_name (uint32_t id);

int windows_export_to_rva (vmi_instance_t , char *, uint32_t *);
int valid_ntoskrnl_start (vmi_instance_t instance, uint32_t addr);


/** Duplicate function from xc_util that should remain
 *  here until Xen 3.1.2 becomes widely distributed.
 */
#ifdef ENABLE_XEN
#ifndef HAVE_MAP_FOREIGN
void *xc_map_foreign_pages(int xc_handle, uint32_t dom, int prot,
                           const xen_pfn_t *arr, int num);
#endif /* HAVE_MAP_FOREIGN */
#endif /* ENABLE_XEN */

#endif /* PRIVATE_H */

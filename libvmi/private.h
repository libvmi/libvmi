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
            int addr_offset;     /**< mm_struct->start_code */
        } linux_instance;
        struct windows_instance{
            uint32_t ntoskrnl;   /**< base phys address for ntoskrnl image */
            uint32_t kddebugger_data64; /**< kernel virtual address for start of KDDEBUGGER_DATA64 structure */
            int tasks_offset;    /**< EPROCESS->ActiveProcessLinks */
            int pdbase_offset;   /**< EPROCESS->Pcb.DirectoryTableBase */
            int pid_offset;      /**< EPROCESS->UniqueProcessId */
            int peb_offset;      /**< EPROCESS->Peb */
            int iba_offset;      /**< EPROCESS->Peb.ImageBaseAddress */
            int ph_offset;       /**< EPROCESS->Peb.ProcessHeap */
        } windows_instance;
    } os;
    void *driver;           /**< driver-specific information */
};

/*----------------------------------------------
 * Convenience functions from convenience.c
 */

/**
 * Typical debug print function.  Only produces output when VMI_DEBUG is
 * defined (usually in libvmi.h) at compile time.
 */
#ifndef VMI_DEBUG
#define dbprint(format, args...) ((void)0)
#else
void dbprint(char *format, ...);
#endif

/**
 */
void errprint (char *format, ...);

/**
 */
void warnprint (char *format, ...);

/**
 */
#define safe_malloc(size) safe_malloc_ (size, __FILE__, __LINE__) 
void *safe_malloc_ (size_t size, char const *file, int line);

unsigned long get_reg32 (reg_t r);

/*----------------------------------------------
 * Utility function from util.c
 */

/**
 * Get the specifid bit from a given register entry.
 *
 * @param[in] reg The register contents to parse (e.g., CR0, CR3, etc)
 * @param[in] bit The number of the bit to check.
 * @param[out] zero if the bit in question is zero, else one
 */
int vmi_get_bit (unsigned long reg, int bit);

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
            vmi_instance_t instance, reg_t cr3,
            uint32_t virt_address);

/**
 * Find the address of the page global directory for a given PID
 *
 * @param[in] instance Handle to xenaccess instance.
 * @param[in] pid The process to lookup.
 *
 * @return Address of pgd, or zero if no address could be found.
 */
reg_t vmi_pid_to_pgd (vmi_instance_t instance, int pid);


//------------------------------------------------
/**
 * Memory maps page in domU that contains given physical address.
 * The mapped memory is read-only.
 *
 * @param[in] instance Handle to xenaccess instance.
 * @param[in] phys_address Requested physical address.
 * @param[out] offset Offset of the address in returned page.
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 *
 * @return Address of a page copy that contains phys_address.
 */
void *vmi_access_pa (
        vmi_instance_t instance, uint32_t phys_address,
        uint32_t *offset, int prot);

/**
 * Memory maps page in domU that contains given machine address. For more
 * info about machine, virtual and pseudo-physical page see xen dev docs.
 *
 * @param[in] instance Handle to xenaccess instance.
 * @param[in] mach_address Requested machine address.
 * @param[out] offset Offset of the address in returned page.
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 *
 * @return Address of a page copy with content like mach_address.
 */
void *vmi_access_ma (
        vmi_instance_t instance, uint32_t mach_address,
        uint32_t *offset, int prot);

/**
 * Memory maps one page from domU to a local address range.  The
 * memory to be mapped is specified with a kernel symbol (e.g.,
 * from System.map on linux).  This memory must be unmapped manually
 * with munmap.
 *
 * @param[in] instance LibVMI instance
 * @param[in] symbol Desired kernel symbol to access
 * @param[out] offset Offset to kernel symbol within the mapped memory
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 * @return Beginning of mapped memory page or NULL on error
 */
void *vmi_access_kernel_sym (
        vmi_instance_t instance, char *symbol, uint32_t *offset, int prot);

/**
 * Memory maps one page from domU to a local address range.  The
 * memory to be mapped is specified with a kernel virtual address.
 * This memory must be unmapped manually with munmap.
 *
 * @param[in] instance LibVMI instance
 * @param[in] virt_address Virtual address to access
 * @param[out] offset Offset to address within the mapped memory
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 * @return Beginning of mapped memory page or NULL on error
 */
void *vmi_access_kernel_va (
        vmi_instance_t instance, uint32_t virt_address,
        uint32_t *offset, int prot);

/**
 * Memory maps multiple pages from domU to a local address range.
 * The memory to be mapped is specified with a kernel virtual
 * address.  This memory must be unmapped manually with munmap.
 *
 * @param[in] instance LibVMI instance
 * @param[in] virt_address Desired virtual address to access
 * @param[in] size Size in bytes of the accessed range
 * @param[out] offset Offset to the address within mapped memory
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 * @return Beginning of the mapped memory pages or NULL on error
 */ 
void *vmi_access_kernel_va_range (
        vmi_instance_t instance, uint32_t virt_address,
        uint32_t size, uint32_t* offset, int prot);

/**
 * Memory maps one page from domU to a local address range.  The
 * memory to be mapped is specified with a virtual address from a 
 * process' address space.  This memory must be unmapped manually
 * with munmap.
 *
 * @param[in] instance LibVMI instance
 * @param[in] virt_address Desired virtual address to access
 * @param[out] offset Offset to address within the mapped memory
 * @param[in] pid PID of process' address space to use.  If you specify
 *     0 here, LibVMI will access the kernel virtual address space and
 *     this function's behavior will be the same as vmi_access_virtual_address.
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 * @return Beginning of mapped memory page or NULL on error
 */
void *vmi_access_user_va (
        vmi_instance_t instance, uint32_t virt_address,
        uint32_t *offset, int pid, int prot);

/**
 * Memory maps multiple pages from domU to a local address range.
 * the memory to be mapped is specified by a virtual address from
 * process' address space.  Data structures that span multiple
 * pages can be mapped without dealing with fragmentation.
 *
 * @param[in] instance LibVMI instance
 * @param[in] virt_address Desired virtual address to access
 * @param[in] size Size in bytes of the accessed range
 * @param[out] offset Offset to the address within mapped memory
 * @param[in] pid PID of process' address space to use.  If you
 *              specify 0 here, LibVMI will access the kernel virtual
 *      address space and this function's be the same as
 *      vmi_access_virtual_range.
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 * @return Beginning of the mapped memory pages or NULL on error
 */
void *vmi_access_user_va_range (
        vmi_instance_t instance, uint32_t virt_address,
        uint32_t size, uint32_t* offset, int pid, int prot);
//-------------------------------------------------

/**
 * Gets address of a symbol in domU virtual memory. It uses System.map
 * file specified in xenaccess configuration file.
 *
 * @param[in] instance Handle to xenaccess instance (see vmi_init).
 * @param[in] symbol Name of the requested symbol.
 * @param[out] address The addres of the symbol in guest memory.
 */
status_t linux_system_map_symbol_to_address (
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

status_t windows_init (vmi_instance_t instance);
status_t linux_init (vmi_instance_t instance);
int get_symbol_row (FILE *f, char *row, char *symbol, int position);
void *vmi_map_page (vmi_instance_t instance, int prot, unsigned long frame_num);
uint32_t windows_find_eprocess (vmi_instance_t instance, char *name);
int vmi_report_error (vmi_instance_t instance, int error, int error_type);
char *linux_predict_sysmap_name (uint32_t id);

status_t windows_export_to_rva (vmi_instance_t , char *, uint32_t *);
status_t valid_ntoskrnl_start (vmi_instance_t instance, uint32_t addr);
status_t windows_kpcr_lookup (vmi_instance_t vmi, char *symbol, uint32_t *address);
uint32_t windows_find_cr3 (vmi_instance_t vmi);

/**
 * Reads a long (32 bit) value from memory, given a machine address.
 *
 * @param[in] instance LibVMI instance
 * @param[in] maddr Machine address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_long_mach (
        vmi_instance_t instance, uint32_t maddr, uint32_t *value);

/**
 * Reads a long long (64 bit) value from memory, given a machine address.
 *
 * @param[in] instance LibVMI instance
 * @param[in] maddr Machine address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_long_long_mach (
        vmi_instance_t instance, uint32_t maddr, uint64_t *value);

/** Duplicate function from xc_util that should remain
 *  here until Xen 3.1.2 becomes widely distributed.
 */
#if ENABLE_XEN == 1
#ifndef HAVE_MAP_FOREIGN
void *xc_map_foreign_pages(int xc_handle, uint32_t dom, int prot,
                           const xen_pfn_t *arr, int num);
#endif /* HAVE_MAP_FOREIGN */
#endif /* ENABLE_XEN */

#endif /* PRIVATE_H */

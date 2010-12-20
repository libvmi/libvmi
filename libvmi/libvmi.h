/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

/**
 * @file libvmi.h
 * @brief The LibVMI API is defined here.
 *
 * More detailed description can go here.
 */
#ifndef LIBVMI_H
#define LIBVMI_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#ifdef ENABLE_XEN
#include <xenctrl.h>
#endif /* ENABLE_XEN */
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>

/* uncomment this to enable debug output */
//#define XA_DEBUG

/**
 * Mode indicating that we are monitoring a live Xen VM
 */
#define XA_MODE_XEN 0

/**
 * Mode indicating that we are viewing a memory image from a disk file
 */
#define XA_MODE_FILE 1

/**
 * Reading from a dd file type (file offset == physical address).  This value
 * is only used when mode equals XA_MODE_FILE.
 */
#define XA_FILETYPE_DD 0

/**
 * Return value indicating success.
 */
#define XA_SUCCESS 0
/**
 * Return value indicating failure.
 */
#define XA_FAILURE -1
/**
 * Failure mode where XenAccess will exit with failure if there are
 * any problems found on startup.  This will provide for strict
 * checking of the configuration file parameters and the memory 
 * image itself.  If initialization completes successfully in this
 * mode, then you should then have full use of the XenAccess memory
 * access functionality (e.g., virtual, physical, and symbolic lookups).
 */
#define XA_FAILHARD 0
/**
 * Failure mode where XenAccess will try to complete initialization
 * unless there is a fatal failure.  Assuming that initialization does
 * complete, memory access may be available with reduced functionality
 * (e.g., only able to access physical addresses).  The exact functionality
 * available will depend on the problems that were bypassed during 
 * initialization.
 */
#define XA_FAILSOFT 1

/**
 * Constant used to specify that the os_type is unknown
 */
#define XA_OS_UNKNOWN 0

/**
 * Constant used to specify Linux in the os_type member of the
 * xa_instance struct.
 */
#define XA_OS_LINUX 1
/**
 * Constant used to specify Windows in the os_type member of the
 * xa_instance struct.
 */
#define XA_OS_WINDOWS 2
/**
 * Constant used to indicate that we are running on a version of Xen
 * that XenAccess does not support.  XenAccess might work, or it might
 * not.  This is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_UNKNOWN 0
/**
 * Constant used to indicate that we are running on Xen 3.0.4.  This
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_0_4 1
/**
 * Constant used to indicate that we are running on Xen 3.1.0  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_1_0 2
/**
 * Constant used to indicate that we are running on Xen 3.1.1  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_1_1 3
/**
 * Constant used to indicate that we are running on Xen 3.1.2  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_1_2 4
/**
 * Constant used to indicate that we are running on Xen 3.1.3  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_1_3 5
/**
 * Constant used to indicate that we are running on Xen 3.1.4  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_1_4 6
/**
 * Constant used to indicate that we are running on Xen 3.2.0  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_2_0 7
/**
 * Constant used to indicate that we are running on Xen 3.2.1  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_2_1 8
/**
 * Constant used to indicate that we are running on Xen 3.2.2  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_2_2 9
/**
 * Constant used to indicate that we are running on Xen 3.2.3  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_2_3 10
/**
 * Constant used to indicate that we are running on Xen 3.3.0  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_3_0 11
/**
 * Constant used to indicate that we are running on Xen 3.3.1  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_3_1 12
/**
 * Constant used to indicate that we are running on Xen 3.4.0  This 
 * is used in the xen_version member of the xa_instance struct.
 */
#define XA_XENVER_3_4_0 13

struct xa_cache_entry{
    time_t last_used;
    char *symbol_name;
    uint32_t virt_address;
    uint32_t mach_address;
    int pid;
    struct xa_cache_entry *next;
    struct xa_cache_entry *prev;
};
typedef struct xa_cache_entry* xa_cache_entry_t;

struct xa_pid_cache_entry{
    time_t last_used;
    int pid;
    uint32_t pgd;
    struct xa_pid_cache_entry *next;
    struct xa_pid_cache_entry *prev;
};
typedef struct xa_pid_cache_entry* xa_pid_cache_entry_t;

/**
 * @brief XenAccess instance.
 *
 * This struct holds all of the relavent information for an instance of
 * XenAccess.  Each time a new domain is accessed, a new instance must
 * be created using the xa_init function.  When you are done with an instance,
 * its resources can be freed using the xa_destroy function.
 */
typedef struct xa_instance{
    uint32_t mode;          /**< file or xen VM data source */
    uint32_t error_mode;    /**< XA_FAILHARD or XA_FAILSOFT */
    char *sysmap;           /**< system map file for domain's running kernel */
    char *image_type;       /**< image type that we are accessing */
    uint32_t page_offset;   /**< page offset for this instance */
    uint32_t page_shift;    /**< page shift for last mapped page */
    uint32_t page_size;     /**< page size for last mapped page */
    uint32_t kpgd;          /**< kernel page global directory */
    uint32_t init_task;     /**< address of task struct for init */
    int os_type;            /**< type of os: XA_OS_LINUX, etc */
    int hvm;                /**< nonzero if HVM memory image */
    int pae;                /**< nonzero if PAE is enabled */
    int pse;                /**< nonzero if PSE is enabled */
    uint32_t cr3;           /**< value in the CR3 register */
    xa_cache_entry_t cache_head;         /**< head of the address cache list */
    xa_cache_entry_t cache_tail;         /**< tail of the address cache list */
    int current_cache_size;              /**< size of the address cache list */
    xa_pid_cache_entry_t pid_cache_head; /**< head of the pid cache list */
    xa_pid_cache_entry_t pid_cache_tail; /**< tail of the pid cache list */
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
} xa_instance_t;

/**
 * @brief Linux task information.
 *
 * This struct holds the task addresses that are found in a task's
 * memory descriptor.  You can fill the values in the struct using
 * the xa_linux_get_taskaddr function.  The comments next to each
 * entry are taken from Bovet & Cesati's excellent book Understanding
 * the Linux Kernel 3rd Ed, p354.
 */
typedef struct xa_linux_taskaddr{
    unsigned long start_code;  /**< initial address of executable code */
    unsigned long end_code;    /**< final address of executable code */
    unsigned long start_data;  /**< initial address of initialized data */
    unsigned long end_data;    /**< final address of initialized data */
    unsigned long start_brk;   /**< initial address of the heap */
    unsigned long brk;         /**< current final address of the heap */
    unsigned long start_stack; /**< initial address of user mode stack */
    unsigned long arg_stack;   /**< initial address of command-line arguments */
    unsigned long arg_end;     /**< final address of command-line arguments */
    unsigned long env_start;   /**< initial address of environmental vars */
    unsigned long env_end;     /**< final address of environmental vars */
} xa_linux_taskaddr_t;

/**
 * @brief Windows PEB information.
 *
 * This struct holds process information found in the PEB, which is 
 * part of the EPROCESS structure.  You can fill the values in the
 * struct using the xa_windows_get_peb function.  Note that this
 * struct does not contain all information from the PEB.
 */
typedef struct xa_windows_peb{
    uint32_t ImageBaseAddress; /**< initial address of executable code */
    uint32_t ProcessHeap;      /**< initial address of the heap */
} xa_windows_peb_t;

/*--------------------------------------------------------
 * Initialization and Destruction functions from xa_core.c
 */

/**
 * Initializes access to a specific domU given a domain name.  All
 * calls to xa_init must eventually call xa_destroy.
 *
 * This function will fail if any problems are detected upon init.
 * If you want to use XenAccess with reduced functionality instead
 * of failing during initialization, then use the lax function instead.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per domain, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * @param[in] domain_name Domain name to access, specified as a string
 * @param[out] instance Struct that holds instance information
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_init_vm_name_strict (char *domain_name, xa_instance_t *instance);

/**
 * Initializes access to a specific domU given a domain name.  All
 * calls to xa_init must eventually call xa_destroy.
 *
 * This function will init unless a critical error is found.  In some
 * cases minor errors can lead to reduced functionality.  If you want
 * to ensure that XenAccess has full functionality, then use the
 * strict function instead.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per domain, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * @param[in] domain_name Domain name to access, specified as a string
 * @param[out] instance Struct that holds instance information
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_init_vm_name_lax (char *domain_name, xa_instance_t *instance);

/**
 * Initializes access to a specific domU given a domain id.  The
 * domain id must represent an active domain and must be > 0.  All
 * calls to xa_init must eventually call xa_destroy.
 *
 * This function will fail if any problems are detected upon init.
 * If you want to use XenAccess with reduced functionality instead
 * of failing during initialization, then use the lax function instead.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per domain, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * @param[in] domain_id Domain id to access, specified as a number
 * @param[out] instance Struct that holds instance information
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_init_vm_id_strict (uint32_t domain_id, xa_instance_t *instance);

/**
 * Initializes access to a specific domU given a domain id.  The
 * domain id must represent an active domain and must be > 0.  All
 * calls to xa_init must eventually call xa_destroy.
 *
 * This function will init unless a critical error is found.  In some
 * cases minor errors can lead to reduced functionality.  If you want
 * to ensure that XenAccess has full functionality, then use the
 * strict function instead.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per domain, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * @param[in] domain_id Domain id to access, specified as a number
 * @param[out] instance Struct that holds instance information
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_init_vm_id_lax (uint32_t domain_id, xa_instance_t *instance);

/**
 * Initializes access to a memory image stored in the given file.  All
 * calls to xa_init_file must eventually call xa_destroy.
 *
 * This function will fail if any problems are detected upon init.
 * If you want to use XenAccess with reduced functionality instead
 * of failing during initialization, then use the lax function instead.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per file, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * @param[in] filename Name of memory image file
 * @param[in] image_type Name of config file entry for this image
 * @param[out] instance Struct that holds instance information
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_init_file_strict
    (char *filename, char *image_type, xa_instance_t *instance);

/**
 * Initializes access to a memory image stored in the given file.  All
 * calls to xa_init_file must eventually call xa_destroy.
 *
 * This function will init unless a critical error is found.  In some
 * cases minor errors can lead to reduced functionality.  If you want
 * to ensure that XenAccess has full functionality, then use the
 * strict function instead.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per file, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * @param[in] filename Name of memory image file
 * @param[in] image_type Name of config file entry for this image
 * @param[out] instance Struct that holds instance information
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_init_file_lax
    (char *filename, char *image_type, xa_instance_t *instance);

/**
 * Destroys an instance by freeing memory and closing any open handles.
 *
 * @param[in] instance Instance to destroy
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_destroy (xa_instance_t *instance);

/*-----------------------------------------
 * Memory access functions from xa_memory.c
 */

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
void *xa_access_pa (
        xa_instance_t *instance, uint32_t phys_address,
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
void *xa_access_ma (
        xa_instance_t *instance, uint32_t mach_address,
        uint32_t *offset, int prot);

/**
 * Memory maps one page from domU to a local address range.  The
 * memory to be mapped is specified with a kernel symbol (e.g.,
 * from System.map on linux).  This memory must be unmapped manually
 * with munmap.
 *
 * @param[in] instance XenAccess instance
 * @param[in] symbol Desired kernel symbol to access
 * @param[out] offset Offset to kernel symbol within the mapped memory
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 * @return Beginning of mapped memory page or NULL on error
 */
void *xa_access_kernel_sym (
        xa_instance_t *instance, char *symbol, uint32_t *offset, int prot);

/**
 * Memory maps one page from domU to a local address range.  The
 * memory to be mapped is specified with a kernel virtual address.
 * This memory must be unmapped manually with munmap.
 *
 * @param[in] instance XenAccess instance
 * @param[in] virt_address Virtual address to access
 * @param[out] offset Offset to address within the mapped memory
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 * @return Beginning of mapped memory page or NULL on error
 */
void *xa_access_kernel_va (
        xa_instance_t *instance, uint32_t virt_address,
        uint32_t *offset, int prot);

/**
 * Memory maps multiple pages from domU to a local address range.
 * The memory to be mapped is specified with a kernel virtual
 * address.  This memory must be unmapped manually with munmap.
 *
 * @param[in] instance XenAccess instance
 * @param[in] virt_address Desired virtual address to access
 * @param[in] size Size in bytes of the accessed range
 * @param[out] offset Offset to the address within mapped memory
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 * @return Beginning of the mapped memory pages or NULL on error
 */ 
void *xa_access_kernel_va_range (
	xa_instance_t* instance, uint32_t virt_address,
	uint32_t size, uint32_t* offset, int prot);

/**
 * Memory maps one page from domU to a local address range.  The
 * memory to be mapped is specified with a virtual address from a 
 * process' address space.  This memory must be unmapped manually
 * with munmap.
 *
 * @param[in] instance XenAccess instance
 * @param[in] virt_address Desired virtual address to access
 * @param[out] offset Offset to address within the mapped memory
 * @param[in] pid PID of process' address space to use.  If you specify
 *     0 here, XenAccess will access the kernel virtual address space and
 *     this function's behavior will be the same as xa_access_virtual_address.
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 * @return Beginning of mapped memory page or NULL on error
 */
void *xa_access_user_va (
        xa_instance_t *instance, uint32_t virt_address,
        uint32_t *offset, int pid, int prot);

/**
 * Memory maps multiple pages from domU to a local address range.
 * the memory to be mapped is specified by a virtual address from
 * process' address space.  Data structures that span multiple
 * pages can be mapped without dealing with fragmentation.
 *
 * @param[in] instance XenAccess instance
 * @param[in] virt_address Desired virtual address to access
 * @param[in] size Size in bytes of the accessed range
 * @param[out] offset Offset to the address within mapped memory
 * @param[in] pid PID of process' address space to use.  If you
 * 		specify 0 here, XenAccess will access the kernel virtual
 *  	address space and this function's be the same as
 *  	xa_access_virtual_range.
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 * @return Beginning of the mapped memory pages or NULL on error
 */
void *xa_access_user_va_range (
	xa_instance_t* instance, uint32_t virt_address,
	uint32_t size, uint32_t* offset, int pid, int prot);

/**
 * Performs the translation from a kernel virtual address to a
 * physical address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] virt_address Desired kernel virtual address to translate
 * @return Physical address, or zero on error
 */
uint32_t xa_translate_kv2p(xa_instance_t *instance, uint32_t virt_address);

/*---------------------------------------
 * Memory access functions from xa_util.c
 */

/**
 * Reads a long (32 bit) value from memory, given a kernel symbol.
 *
 * @param[in] instance XenAccess instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_read_long_sym (xa_instance_t *instance, char *sym, uint32_t *value);

/**
 * Reads a long long (64 bit) value from memory, given a kernel symbol.
 *
 * @param[in] instance XenAccess instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_read_long_long_sym (xa_instance_t *instance, char *sym, uint64_t *value);

/**
 * Reads a long (32 bit) value from memory, given a virtual address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_read_long_virt (
        xa_instance_t *instance, uint32_t vaddr, int pid, uint32_t *value);

/**
 * Reads a long long (64 bit) value from memory, given a virtual address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_read_long_long_virt (
        xa_instance_t *instance, uint32_t vaddr, int pid, uint64_t *value);

/**
 * Reads a long (32 bit) value from memory, given a physical address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_read_long_phys (
        xa_instance_t *instance, uint32_t paddr, uint32_t *value);

/**
 * Reads a long long (64 bit) value from memory, given a physical address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_read_long_long_phys (
        xa_instance_t *instance, uint32_t paddr, uint64_t *value);

/**
 * Reads a long (32 bit) value from memory, given a machine address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] maddr Machine address to read from
 * @param[out] value The value read from memory
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_read_long_mach (
        xa_instance_t *instance, uint32_t maddr, uint32_t *value);

/**
 * Reads a long long (64 bit) value from memory, given a machine address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] maddr Machine address to read from
 * @param[out] value The value read from memory
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_read_long_long_mach (
        xa_instance_t *instance, uint32_t maddr, uint64_t *value);

/**
 * Looks up the virtual address of an exported kernel symbol.
 *
 * @param[in] instance XenAccess instance
 * @param[in] sym Kernel symbol (must be exported)
 * @param[out] vaddr The virtual address of the symbol
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_symbol_to_address (xa_instance_t *instance, char *sym, uint32_t *vaddr);

/*-----------------------------
 * Linux-specific functionality
 */

/**
 * Extracts information about the specified process' location in memory from
 * the task struct specified by @a pid.
 *
 * @param[in] instance XenAccess instance
 * @param[in] pid The PID for the task to read from
 * @param[out] taskaddr Information from the specified task struct
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_linux_get_taskaddr (
        xa_instance_t *instance, int pid, xa_linux_taskaddr_t *taskaddr);

/*-----------------------------
 * Windows-specific functionality
 */

/**
 * Extracts information from the PEB struct, which is located at the top of
 * the EPROCESS struct with the specified @a pid.
 *
 * @param[in] instance XenAccess instance
 * @param[in] pid The unique ID for the PEB to read from
 * @param[out] peb Information from the specified PEB
 * @return XA_SUCCESS or XA_FAILURE
 */
int xa_windows_get_peb (
        xa_instance_t *instance, int pid, xa_windows_peb_t *peb);

#endif /* LIBVMI_H */

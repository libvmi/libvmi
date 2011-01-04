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
#pragma GCC visibility push(default)

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>

/* uncomment this to enable debug output */
//TODO make this a switch to configure instead
//#define VMI_DEBUG

typedef enum mode{
    VMI_MODE_XEN,  /**< mode indicating that we are monitoring a Xen VM */
    VMI_MODE_KVM,  /**< mode indicating that we are monitoring a KVM VM */
    VMI_MODE_FILE  /**< mode indicating that we are viewing a file on disk */
} mode_t;

/**
 * Reading from a dd file type (file offset == physical address).  This value
 * is only used when mode equals VMI_MODE_FILE.
 */
#define VMI_FILETYPE_DD 0

typedef enum status{
    VMI_SUCCESS,  /**< return value indicating success */
    VMI_FAILURE   /**< return value indicating failure */
} status_t;

/**
 * Failure mode where XenAccess will exit with failure if there are
 * any problems found on startup.  This will provide for strict
 * checking of the configuration file parameters and the memory 
 * image itself.  If initialization completes successfully in this
 * mode, then you should then have full use of the XenAccess memory
 * access functionality (e.g., virtual, physical, and symbolic lookups).
 */
#define VMI_FAILHARD 0
/**
 * Failure mode where XenAccess will try to complete initialization
 * unless there is a fatal failure.  Assuming that initialization does
 * complete, memory access may be available with reduced functionality
 * (e.g., only able to access physical addresses).  The exact functionality
 * available will depend on the problems that were bypassed during 
 * initialization.
 */
#define VMI_FAILSOFT 1

typedef enum os{
    VMI_OS_UNKNOWN,  /**< OS type is unknown */
    VMI_OS_LINUX,    /**< OS type is Linux */
    VMI_OS_WINDOWS   /**< OS type is Windows */
} os_t;

typedef unsigned long reg_t;
typedef enum registers{
    REG_CR0,
    REG_CR1,
    REG_CR2,
    REG_CR3,
    REG_CR4
} registers_t;

/**
 * @brief LibVMI Instance.
 *
 * This struct holds all of the relavent information for an instance of
 * LibVMI.  Each time a new domain is accessed, a new instance must
 * be created using the vmi_init function.  When you are done with an instance,
 * its resources can be freed using the vmi_destroy function.
 */
typedef struct vmi_instance * vmi_instance_t;

/**
 * @brief Linux task information.
 *
 * This struct holds the task addresses that are found in a task's
 * memory descriptor.  You can fill the values in the struct using
 * the vmi_linux_get_taskaddr function.  The comments next to each
 * entry are taken from Bovet & Cesati's excellent book Understanding
 * the Linux Kernel 3rd Ed, p354.
 */
typedef struct vmi_linux_taskaddr{
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
} vmi_linux_taskaddr_t;

/**
 * @brief Windows PEB information.
 *
 * This struct holds process information found in the PEB, which is 
 * part of the EPROCESS structure.  You can fill the values in the
 * struct using the vmi_windows_get_peb function.  Note that this
 * struct does not contain all information from the PEB.
 */
typedef struct vmi_windows_peb{
    uint32_t ImageBaseAddress; /**< initial address of executable code */
    uint32_t ProcessHeap;      /**< initial address of the heap */
} vmi_windows_peb_t;

/*--------------------------------------------------------
 * Initialization and Destruction functions from vmi_core.c
 */

/**
 * Initializes access to a specific domU given a domain name.  All
 * calls to vmi_init must eventually call vmi_destroy.
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
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_vm_name_strict (char *domain_name, vmi_instance_t instance);

/**
 * Initializes access to a specific domU given a domain name.  All
 * calls to vmi_init must eventually call vmi_destroy.
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
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_vm_name_lax (char *domain_name, vmi_instance_t instance);

/**
 * Initializes access to a specific domU given a domain id.  The
 * domain id must represent an active domain and must be > 0.  All
 * calls to vmi_init must eventually call vmi_destroy.
 *
 * This function will fail if any problems are detected upon init.
 * If you want to use XenAccess with reduced functionality instead
 * of failing during initialization, then use the lax function instead.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per domain, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * @param[in] id Domain id to access, specified as a number
 * @param[out] instance Struct that holds instance information
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_vm_id_strict (unsigned long id, vmi_instance_t instance);

/**
 * Initializes access to a specific domU given a domain id.  The
 * domain id must represent an active domain and must be > 0.  All
 * calls to vmi_init must eventually call vmi_destroy.
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
 * @param[in] id Domain id to access, specified as a number
 * @param[out] instance Struct that holds instance information
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_vm_id_lax (unsigned long id, vmi_instance_t instance);

/**
 * Initializes access to a memory image stored in the given file.  All
 * calls to vmi_init_file must eventually call vmi_destroy.
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
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_file_strict
    (char *filename, char *image_type, vmi_instance_t instance);

/**
 * Initializes access to a memory image stored in the given file.  All
 * calls to vmi_init_file must eventually call vmi_destroy.
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
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_file_lax
    (char *filename, char *image_type, vmi_instance_t instance);

/**
 * Destroys an instance by freeing memory and closing any open handles.
 *
 * @param[in] instance Instance to destroy
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_destroy (vmi_instance_t instance);

/*-----------------------------------------
 * Memory access functions from vmi_memory.c
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
 * @param[in] instance XenAccess instance
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
 * @param[in] instance XenAccess instance
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
 * @param[in] instance XenAccess instance
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
 * @param[in] instance XenAccess instance
 * @param[in] virt_address Desired virtual address to access
 * @param[out] offset Offset to address within the mapped memory
 * @param[in] pid PID of process' address space to use.  If you specify
 *     0 here, XenAccess will access the kernel virtual address space and
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
 * @param[in] instance XenAccess instance
 * @param[in] virt_address Desired virtual address to access
 * @param[in] size Size in bytes of the accessed range
 * @param[out] offset Offset to the address within mapped memory
 * @param[in] pid PID of process' address space to use.  If you
 * 		specify 0 here, XenAccess will access the kernel virtual
 *  	address space and this function's be the same as
 *  	vmi_access_virtual_range.
 * @param[in] prot Desired memory protection (PROT_READ, PROT_WRITE, etc)
 * @return Beginning of the mapped memory pages or NULL on error
 */
void *vmi_access_user_va_range (
	vmi_instance_t instance, uint32_t virt_address,
	uint32_t size, uint32_t* offset, int pid, int prot);

/**
 * Performs the translation from a kernel virtual address to a
 * physical address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] virt_address Desired kernel virtual address to translate
 * @return Physical address, or zero on error
 */
uint32_t vmi_translate_kv2p(vmi_instance_t instance, uint32_t virt_address);

/*---------------------------------------
 * Memory access functions from vmi_util.c
 */

/**
 * Reads a long (32 bit) value from memory, given a kernel symbol.
 *
 * @param[in] instance XenAccess instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_long_sym (vmi_instance_t instance, char *sym, uint32_t *value);

/**
 * Reads a long long (64 bit) value from memory, given a kernel symbol.
 *
 * @param[in] instance XenAccess instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_long_long_sym (vmi_instance_t instance, char *sym, uint64_t *value);

/**
 * Reads a long (32 bit) value from memory, given a virtual address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_long_virt (
        vmi_instance_t instance, uint32_t vaddr, int pid, uint32_t *value);

/**
 * Reads a long long (64 bit) value from memory, given a virtual address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_long_long_virt (
        vmi_instance_t instance, uint32_t vaddr, int pid, uint64_t *value);

/**
 * Reads a long (32 bit) value from memory, given a physical address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_long_phys (
        vmi_instance_t instance, uint32_t paddr, uint32_t *value);

/**
 * Reads a long long (64 bit) value from memory, given a physical address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_long_long_phys (
        vmi_instance_t instance, uint32_t paddr, uint64_t *value);

/**
 * Reads a long (32 bit) value from memory, given a machine address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] maddr Machine address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_long_mach (
        vmi_instance_t instance, uint32_t maddr, uint32_t *value);

/**
 * Reads a long long (64 bit) value from memory, given a machine address.
 *
 * @param[in] instance XenAccess instance
 * @param[in] maddr Machine address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_long_long_mach (
        vmi_instance_t instance, uint32_t maddr, uint64_t *value);

/**
 * Looks up the virtual address of an exported kernel symbol.
 *
 * @param[in] instance XenAccess instance
 * @param[in] sym Kernel symbol (must be exported)
 * @param[out] vaddr The virtual address of the symbol
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_symbol_to_address (vmi_instance_t instance, char *sym, uint32_t *vaddr);

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
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_linux_get_taskaddr (
        vmi_instance_t instance, int pid, vmi_linux_taskaddr_t *taskaddr);

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
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_windows_get_peb (
        vmi_instance_t instance, int pid, vmi_windows_peb_t *peb);

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
void vmi_print_hex (unsigned char *data, int length);

//TODO document the new functions listed below
os_t vmi_get_ostype (vmi_instance_t vmi);
unsigned long vmi_get_offset (vmi_instance_t vmi, char *offset_name);
unsigned long vmi_get_memsize (vmi_instance_t vmi);

#pragma GCC visibility pop
#endif /* LIBVMI_H */

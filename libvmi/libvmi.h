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

/**
 * @file libvmi.h
 * @brief The LibVMI API is defined here.
 *
 * More detailed description can go here.
 */
#ifndef LIBVMI_H
#define LIBVMI_H

#ifdef __cplusplus
extern "C" {
#endif

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
#include <string.h>

/* uncomment this and recompile to enable debug output */
//#define VMI_DEBUG

/* enable or disable the address cache (v2p, pid, etc) */
#define ENABLE_ADDRESS_CACHE 1

/* enable or disable the page cache */
#define ENABLE_PAGE_CACHE 1

/* max number of pages held in page cache */
#define MAX_PAGE_CACHE_SIZE 512

typedef uint32_t vmi_mode_t;

/* These will be used in conjuction with vmi_mode_t variables */

#define VMI_AUTO (1 << 0)  /**< libvmi should detect what to monitor or view */

#define VMI_XEN  (1 << 1)  /**< libvmi is monitoring a Xen VM */

#define VMI_KVM  (1 << 2)  /**< libvmi is monitoring a KVM VM */

#define VMI_FILE (1 << 3)  /**< libvmi is viewing a file on disk */

#define VMI_INIT_PARTIAL  (1 << 16) /**< init enough to view physical addresses */

#define VMI_INIT_COMPLETE (1 << 17) /**< full initialization */

#define VMI_INIT_EVENTS (1 << 18) /**< init support for memory events */

#define VMI_CONFIG_NONE (1 << 24) /**< no config provided */

#define VMI_CONFIG_GLOBAL_FILE_ENTRY (1 << 25) /**< config in file provided */

#define VMI_CONFIG_STRING (1 << 26) /**< config string provided */

#define VMI_CONFIG_GHASHTABLE (1 << 27) /**< config GHashTable provided */

#define VMI_INVALID_DOMID ~0 /**< invalid domain id */

typedef enum status {

    VMI_SUCCESS,  /**< return value indicating success */

    VMI_FAILURE   /**< return value indicating failure */
} status_t;

typedef enum os {

    VMI_OS_UNKNOWN,  /**< OS type is unknown */

    VMI_OS_LINUX,    /**< OS type is Linux */

    VMI_OS_WINDOWS   /**< OS type is Windows */
} os_t;

typedef enum win_ver {

    VMI_OS_WINDOWS_NONE,    /**< Not Windows */

    VMI_OS_WINDOWS_UNKNOWN, /**< Is Windows, not sure which */
    VMI_OS_WINDOWS_2000,
    VMI_OS_WINDOWS_XP,
    VMI_OS_WINDOWS_2003,
    VMI_OS_WINDOWS_VISTA,
    VMI_OS_WINDOWS_2008,
    VMI_OS_WINDOWS_7
} win_ver_t;

/* Three paging modes from Intel Vol3a Section 4.1.1 */
typedef enum page_mode {

    VMI_PM_UNKNOWN, /**< page mode unknown */

    VMI_PM_LEGACY,  /**< 32-bit paging */

    VMI_PM_PAE,     /**< PAE paging */

    VMI_PM_IA32E    /**< IA-32e paging */
} page_mode_t;

typedef uint64_t reg_t;
typedef enum registers {
    RAX,
    RBX,
    RCX,
    RDX,
    RBP,
    RSI,
    RDI,
    RSP,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,

    RIP,
    RFLAGS,

    CR0,
    CR2,
    CR3,
    CR4,

    DR0,
    DR1,
    DR2,
    DR3,
    DR6,
    DR7,

    CS_SEL,
    DS_SEL,
    ES_SEL,
    FS_SEL,
    GS_SEL,
    SS_SEL,
    TR_SEL,
    LDTR_SEL,

    CS_LIMIT,
    DS_LIMIT,
    ES_LIMIT,
    FS_LIMIT,
    GS_LIMIT,
    SS_LIMIT,
    TR_LIMIT,
    LDTR_LIMIT,
    IDTR_LIMIT,
    GDTR_LIMIT,

    CS_BASE,
    DS_BASE,
    ES_BASE,
    FS_BASE,
    GS_BASE,
    SS_BASE,
    TR_BASE,
    LDTR_BASE,
    IDTR_BASE,
    GDTR_BASE,

    CS_ARBYTES,
    DS_ARBYTES,
    ES_ARBYTES,
    FS_ARBYTES,
    GS_ARBYTES,
    SS_ARBYTES,
    TR_ARBYTES,
    LDTR_ARBYTES,

    SYSENTER_CS,
    SYSENTER_ESP,
    SYSENTER_EIP,

    SHADOW_GS,

    MSR_FLAGS,
    MSR_LSTAR,
    MSR_CSTAR,
    MSR_SYSCALL_MASK,
    MSR_EFER,
    MSR_TSC_AUX,
    
    /* special generic case for handling MSRs, given their understandably
     *  generic treatment for events in Xen and elsewhere. Not relevant for 
     *  vCPU get/set of register data.
     */
    MSR_ALL,

    TSC
} registers_t;

/* type def for forward compatibility with 64-bit guests */
typedef uint64_t addr_t;

/**
 * Generic representation of Unicode string to be used within libvmi
 */
typedef struct _ustring {

    size_t length;         /**< byte count of contents */

    uint8_t *contents;     /**< pointer to byte array holding string */

    const char *encoding;  /**< holds iconv-compatible encoding of contents; do not free */
} unicode_string_t;

/* custom config input source */
typedef void* vmi_config_t;

/**
 * @brief LibVMI Instance.
 *
 * This struct holds all of the relavent information for an instance of
 * LibVMI.  Each time a new domain is accessed, a new instance must
 * be created using the vmi_init function.  When you are done with an instance,
 * its resources can be freed using the vmi_destroy function.
 */
typedef struct vmi_instance *vmi_instance_t;

/*---------------------------------------------------------
 * Initialization and Destruction functions from core.c
 */

/**
 * Initializes access to a specific VM or file given a name.  All
 * calls to vmi_init must eventually call vmi_destroy.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per VM or file, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * @param[out] vmi Struct that holds instance information
 * @param[in] flags VMI_AUTO, VMI_XEN, VMI_KVM, or VMI_FILE plus
 *  VMI_INIT_PARTIAL or VMI_INIT_COMPLETE
 * @param[in] name Unique name specifying the VM or file to view
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init(
    vmi_instance_t *vmi,
    uint32_t flags,
    char *name);

/**
 * Initializes access to a specific VM with a custom configuration source.  All
 * calls to vmi_init_custom must eventually call vmi_destroy.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per VM or file, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * @param[out] vmi Struct that holds instance information
 * @param[in] flags VMI_AUTO, VMI_XEN, VMI_KVM, or VMI_FILE plus
 *  VMI_INIT_PARTIAL or VMI_INIT_COMPLETE plus
 *  VMI_CONFIG_FILE/STRING/GHASHTABLE
 * @param[in] config Pointer to the specified configuration structure
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_custom(
    vmi_instance_t *vmi,
    uint32_t flags,
    vmi_config_t config);

/**
 * Completes initialization.  Call this after calling vmi_init with
 * VMI_INIT_PARTIAL.  Calling this at any other time results in undefined
 * behavior.  The partial init provides physical memory access only.  So
 * the purpose of this function is to allow for a staged init of LibVMI.
 * You can gain physical memory access, run some heuristics to obtain
 * the necessary offsets, and then complete the init.
 *
 * @param[in,out] vmi Struct that holds the instance information and was
 *  passed to vmi_init with a VMI_INIT_PARTIAL flag
 * @param[in] config Pointer to a string containing the config entries for
 *  this domain.  Entries should be specified as in the config file
 *  (e.g., '{ostype = "Windows"; win_tasks = 0x88; win_pdbase = 0x18; ...}').
 *  If this is NULL, then the config is pulled from /etc/libvmi.conf.
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_complete(
    vmi_instance_t *vmi,
    char *config);

/**
 * Completes initialization.  Call this after calling vmi_init or vmi_init_custom
 * with VMI_INIT_PARTIAL.  Calling this at any other time results in undefined
 * behavior.  The partial init provides physical memory access only.  So
 * the purpose of this function is to allow for a staged init of LibVMI.
 * You can gain physical memory access, run some heuristics to obtain
 * the necessary offsets, and then complete the init.
 *
 * @param[in,out] vmi Struct that holds the instance information and was
 *  passed to vmi_init with a VMI_INIT_PARTIAL flag
 * @param[in] flags VMI_CONFIG_FILE/STRING/GHASHTABLE
 * @param[in] config Pointer to a structure containing the config entries for
 *  this domain.
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_complete_custom(
    vmi_instance_t *vmi,
    uint32_t flags,
    vmi_config_t config);

/**
 * Destroys an instance by freeing memory and closing any open handles.
 *
 * @param[in] vmi Instance to destroy
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_destroy(
    vmi_instance_t vmi);

/*---------------------------------------------------------
 * Memory translation functions from memory.c
 */

/**
 * Performs the translation from a kernel virtual address to a
 * physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Desired kernel virtual address to translate
 * @return Physical address, or zero on error
 */
addr_t vmi_translate_kv2p(
    vmi_instance_t vmi,
    addr_t vaddr);

/**
 * Performs the translation from a user virtual address to a
 * physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Desired kernel virtual address to translate
 * @param[in] pid Process id for desired user address space
 * @return Physical address, or zero on error
 */
addr_t vmi_translate_uv2p(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid);

/**
 * Performs the translation from a kernel symbol to a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] symbol Desired kernel symbol to translate
 * @return Virtual address, or zero on error
 */
addr_t vmi_translate_ksym2v(
    vmi_instance_t vmi,
    char *symbol);

/**
 * Performs the translation from a symbol to a virtual address.
 * On Windows this function walks the PE export table.
 * Linux is unimplemented at this time.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] base_vaddr Base virtual address (beginning of PE header in Windows)
 * @param[in] pid PID
 * @param[in] symbol Desired symbol to translate
 * @return Virtual address, or zero on error
 */
addr_t vmi_translate_sym2v(
    vmi_instance_t vmi,
    addr_t base_vaddr,
    uint32_t pid,
    char *symbol);

/**
 * Performs the translation from an RVA to a symbol
 * On Windows this function walks the PE export table.
 * Linux is unimplemented at this time.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] base_vaddr Base virtual address (beginning of PE header in Windows)
 * @param[in] pid PID
 * @param[in] rva RVA to translate
 * @return Symbol, or NULL on error
 */
const char* vmi_translate_v2sym(
    vmi_instance_t vmi,
    addr_t base_vaddr,
    uint32_t pid,
    addr_t rva);

/**
 * Given a pid, this function returns the virtual address of the
 * directory table base for this process' address space.  This value
 * is effectively what would be in the CR3 register while this process
 * is running.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] pid Desired process id to lookup
 * @return The directory table base virtual address for \a pid
 */
addr_t vmi_pid_to_dtb(
    vmi_instance_t vmi,
    int pid);

/**
 * Given a dtb, this function returns the PID corresponding to the
 * virtual address of the directory table base.
 * This function does NOT implement caching as to avoid false mappings.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] dtb Desired dtb to lookup
 * @return The PID corresponding to the dtb
 */
int vmi_dtb_to_pid(
    vmi_instance_t vmi,
    addr_t dtb);

/**
 * Translates a virtual address to a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] dtb address of the relevant page directory base
 * @param[in] vaddr virtual address to translate via dtb
 * @return Physical address, or zero on error
 */

addr_t vmi_pagetable_lookup (
    vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr);

/*---------------------------------------------------------
 * Memory access functions from util.c
 */

/**
 * Reads \a count bytes from memory located at the kernel symbol \a sym
 * and stores the output in \a buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] buf The data read from memory
 * @param[in] count The number of bytes to read
 * @return The number of bytes read.
 */
size_t vmi_read_ksym(
    vmi_instance_t vmi,
    char *sym,
    void *buf,
    size_t count);

/**
 * Reads \a count bytes from memory located at the virtual address \a vaddr
 * and stores the output in \a buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] buf The data read from memory
 * @param[in] count The number of bytes to read
 * @return The number of bytes read.
 */
size_t vmi_read_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    void *buf,
    size_t count);

/**
 * Reads \a count bytes from memory located at the physical address \a paddr
 * and stores the output in \a buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] buf The data read from memory
 * @param[in] count The number of bytes to read
 * @return The number of bytes read.
 */
size_t vmi_read_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    size_t count);

/**
 * Reads 8 bits from memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_8_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint8_t * value);

/**
 * Reads 16 bits from memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_16_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint16_t * value);

/**
 * Reads 32 bits from memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_32_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint32_t * value);

/**
 * Reads 64 bits from memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_64_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint64_t * value);

/**
 * Reads an address from memory, given a kernel symbol.  The number of
 * bytes read is 8 for 64-bit systems and 4 for 32-bit systems.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_addr_ksym(
    vmi_instance_t vmi,
    char *sym,
    addr_t *value);

/**
 * Reads a null-terminated string from memory, starting at
 * the given kernel symbol.  The returned value must be
 * freed by the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol for memory location where string starts
 * @return String read from memory or NULL on error
 */
char *vmi_read_str_ksym(
    vmi_instance_t vmi,
    char *sym);

/**
 * Reads 8 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_8_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    uint8_t * value);

/**
 * Reads 16 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_16_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    uint16_t * value);

/**
 * Reads 32 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_32_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    uint32_t * value);

/**
 * Reads 64 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_64_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    uint64_t * value);

/**
 * Reads an address from memory, given a virtual address.  The number of
 * bytes read is 8 for 64-bit systems and 4 for 32-bit systems.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_addr_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    addr_t *value);

/**
 * Reads a null terminated string from memory, starting at
 * the given virtual address.  The returned value must be
 * freed by the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address for start of string
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @return String read from memory or NULL on error
 */
char *vmi_read_str_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid);

/**
 * Reads a Unicode string from the given address. If the guest is running
 * Windows, a UNICODE_STRING struct is read. Linux is not yet
 * supported. The returned value must be freed by the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address of the UNICODE_STRING structure
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @return String read from memory or NULL on error; this function
 *         will set the encoding field.
 */
unicode_string_t *vmi_read_unicode_str_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid);

/**
 * Converts character encoding from that in the input string to another
 * specified encoding. Two common ways to use this function are: (1) convert a
 * string to the "UTF-8" encoding and output with printf("%s"); (2) convert a
 * string to the "WCHAR_T" encoding and output with printf("%ls").
 *
 * @param[in] in  unicode_string_t to be converted; encoding field must be set
 * @param[in] out output unicode_string_t, allocated by caller (this function allocates the contents field)
 * @param[in] outencoding output encoding, must be compatible with the iconv function
 * @return status code
 */
status_t vmi_convert_str_encoding(
    const unicode_string_t *in,
    unicode_string_t *out,
    const char *outencoding);

/**
 * Convenience function to free a unicode_string_t struct.
 *
 * @param[in] p_us Pointer to a unicode_string_t struct
 */
void vmi_free_unicode_str(
    unicode_string_t *p_us);

/**
 * Reads 8 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_8_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint8_t * value);

/**
 * Reads 16 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_16_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint16_t * value);

/**
 * Reads 32 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_32_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t * value);

/**
 * Reads 64 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_64_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint64_t * value);

/**
 * Reads an address from memory, given a physical address.  The number of
 * bytes read is 8 for 64-bit systems and 4 for 32-bit systems.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_addr_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    addr_t *value);

/**
 * Reads a nul terminated string from memory, starting at
 * the given physical address.  The returned value must be
 * freed by the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address for start of string
 * @return String read from memory or NULL on error
 */
char *vmi_read_str_pa(
    vmi_instance_t vmi,
    addr_t paddr);

/**
 * Writes \a count bytes to memory located at the kernel symbol \a sym
 * from \a buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to write to
 * @param[in] buf The data written to memory
 * @param[in] count The number of bytes to write
 * @return The number of bytes written.
 */
size_t vmi_write_ksym(
    vmi_instance_t vmi,
    char *sym,
    void *buf,
    size_t count);

/**
 * Writes \a count bytes to memory located at the virtual address \a vaddr
 * from \a buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to write to
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] buf The data written to memory
 * @param[in] count The number of bytes to write
 * @return The number of bytes written.
 */
size_t vmi_write_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    void *buf,
    size_t count);

/**
 * Writes \a count bytes to memory located at the physical address \a paddr
 * from \a buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to write to
 * @param[in] buf The data written to memory
 * @param[in] count The number of bytes to write
 * @return The number of bytes written.
 */
size_t vmi_write_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    size_t count);

/**
 * Writes 8 bits to memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_8_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint8_t * value);

/**
 * Writes 16 bits to memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_16_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint16_t * value);

/**
 * Writes 32 bits to memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_32_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint32_t * value);

/**
 * Writes 64 bits to memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_64_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint64_t * value);

/**
 * Writes 8 bits to memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to write to
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_8_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    uint8_t * value);

/**
 * Writes 16 bits to memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to write to
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_16_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    uint16_t * value);

/**
 * Writes 32 bits to memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to write to
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_32_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    uint32_t * value);

/**
 * Writes 64 bits to memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to write to
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_64_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    uint64_t * value);

/**
 * Writes 8 bits to memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_8_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint8_t * value);

/**
 * Writes 16 bits to memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_16_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint16_t * value);

/**
 * Writes 32 bits to memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_32_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t * value);

/**
 * Writes 64 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_64_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint64_t * value);

/*---------------------------------------------------------
 * Print util functions from pretty_print.c
 */

/**
 * Prints out the hex and ascii version of a chunk of bytes. The
 * output is similar to what you would get with 'od -h' with the
 * additional ascii information on the right side of the display.
 *
 * @param[in] data The bytes that will be printed to stdout
 * @param[in] length The length (in bytes) of data
 */
void vmi_print_hex(
    unsigned char *data,
    unsigned long length);

/**
 * Prints out the hex and ascii version of a chunk of bytes. The
 * output is similar to what you would get with 'od -h' with the
 * additional ascii information on the right side of the display.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to use as starting address
 * @param[in] length The length (in bytes) of data to print
 */
void vmi_print_hex_ksym(
    vmi_instance_t vmi,
    char *sym,
    size_t length);

/**
 * Prints out the hex and ascii version of a chunk of bytes. The
 * output is similar to what you would get with 'od -h' with the
 * additional ascii information on the right side of the display.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to use as starting address
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] length The length (in bytes) of data to print
 */
void vmi_print_hex_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    int pid,
    size_t length);

/**
 * Prints out the hex and ascii version of a chunk of bytes. The
 * output is similar to what you would get with 'od -h' with the
 * additional ascii information on the right side of the display.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to use as starting address
 * @param[in] length The length (in bytes) of data to print
 */
void vmi_print_hex_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    size_t length);

/*---------------------------------------------------------
 * Accessor functions from accessors.c
 */

/**
 * Gets the name of the VM (or file) that LibVMI is accessing.
 *
 * @param[in] vmi LibVMI instance
 * @return VM (or file) name, must be free'd by caller
 */
char *vmi_get_name(
    vmi_instance_t vmi);

/**
 * Gets the id of the VM that LibVMI is accessing.
 *
 * @param[in] vmi LibVMI instance
 * @return VM id, or zero on error
 */
unsigned long vmi_get_vmid(
    vmi_instance_t vmi);

/**
 * Gets the current access mode for LibVMI, which tells what
 * resource is being using to access the memory (e.g., VMI_XEN,
 * VMI_KVM, or VMI_FILE).
 *
 * @param[in] vmi LibVMI instance
 * @return Access mode
 */
uint32_t vmi_get_access_mode(
    vmi_instance_t vmi);

/**
 * Gets the current page mode for LibVMI, which tells what
 * type of address translation is in use (e.g., VMI_PM_LEGACY,
 * VMI_PM_PAE, or VMI_PM_IA32E).
 * 
 * If paging mode is altered after vmi_init, the information 
 *  preserved in vmi_instance_t will have become stale and 
 *  require re-initialization.
 *
 * @param[in] vmi LibVMI instance
 * @return Page mode
 */
page_mode_t vmi_get_page_mode(
    vmi_instance_t vmi);

/**
 * Gets the current address width for the given vmi_instance_t
 *
 * Note: relative to the OS mode, not that of a process. 
 *       Also, if paging mode is altered after vmi_init,
 *       the information as recorded in vmi_instance_t will
 *       be stale and require re-initialization.
 *
 * @param[in] vmi LibVMI instance
 * @return address size in bytes
 */
uint8_t vmi_get_address_width(
    vmi_instance_t vmi);

/**
 * Get the OS type that LibVMI is currently accessing.  This is
 * simple windows or linux (no version information).
 *
 * @param[in] vmi LibVMI instance
 * @return OS type
 */
os_t vmi_get_ostype(
    vmi_instance_t vmi);

/**
 * Get the version of Windows that LibVMI is currently accessing.  This is the
 * simple Windows version - no service pack or patch level is provided.
 *
 * @param[in] vmi LibVMI instance
 * @return Windows version
 */
win_ver_t vmi_get_winver(
    vmi_instance_t vmi);

/**
 * Get string represenatation of the version of Windows that LibVMI is currently accessing.
 *
 * @param[in] vmi LibVMI instance
 * @return string description of Windows version (do not free)
 */
const char *vmi_get_winver_str(
    vmi_instance_t vmi);

/**
 * Get the version of Windows based on the provided KDVB address.  This is the
 * simple Windows version - no service pack or patch level is provided.
 *
 * This function is intended to be used during partial init as an aid to elevate
 * to full init.
 *
 * @param[in] vmi       LibVMI instance
 * @param[in] kdvb_pa   The physical address of the KDVB
 * @return Windows version
 */
win_ver_t vmi_get_winver_manual(
    vmi_instance_t vmi,
    addr_t kdvb_pa);

/**
 * Get the memory offset associated with the given offset_name.
 * Valid names include everything in the /etc/libvmi.conf file.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] offset_name String name for desired offset
 * @return The offset value
 */
unsigned long vmi_get_offset(
    vmi_instance_t vmi,
    char *offset_name);

/**
 * Gets the memory size of the guest or file that LibVMI is currently
 * accessing.  This is effectively the max physical address that you
 * can access in the system.
 *
 * NOTE: if memory ballooning alters the allocation of memory to a 
 *  VM after vmi_init, this information will have become stale
 *  and a re-initialization will be required.
 *
 * @param[in] vmi LibVMI instance
 * @return Memory size
 */
unsigned long vmi_get_memsize(
    vmi_instance_t vmi);

/**
 * Gets the memory size of the guest that LibVMI is accessing.
 * This information is required for any interaction with of VCPU registers.
 *
 * @param[in] vmi LibVMI instance
 * @return Number of VCPUs
 */
unsigned int vmi_get_num_vcpus (
    vmi_instance_t vmi);

/**
 * Gets the current value of a VCPU register.  This currently only
 * supports control registers.  When LibVMI is accessing a raw
 * memory file, this function will fail.
 *
 * NOTE: for some hypervisor drivers, it is important to understand
 *  the validity of the values that registers hold. For example,
 *  CR3 for Xen paravirtual VMs may hold a physical address higher than
 *  the maximum psuedophysical address of the given VM (this is an
 *  expected and correct idiosyncrasy of that platform). 
 *  Similar scenarios exist for IDTR, etc.
 *
 * @param[in] vmi LibVMI instance
 * @param[out] value Returned value from the register, only valid on VMI_SUCCESS
 * @param[in] reg The register to access
 * @param[in] vcpu The index of the VCPU to access, use 0 for single VCPU systems
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu);

/**
 * Sets the current value of a VCPU register.  This currently only
 * supports control registers.  When LibVMI is accessing a raw
 * memory file, this function will fail. Operating upon an unpaused
 * VM with this function is likely to have unexpected results.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] value Value to assign to the register
 * @param[in] reg The register to access
 * @param[in] vcpu The index of the VCPU to access, use 0 for single VCPU systems
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_set_vcpureg(
    vmi_instance_t vmi,
    reg_t value,
    registers_t reg,
    unsigned long vcpu);

/**
 * Pauses the VM.  Use vmi_resume_vm to resume the VM after pausing
 * it.  If accessing a memory file, this has no effect.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_pause_vm(
    vmi_instance_t vmi);

/**
 * Resumes the VM.  Use vmi_pause_vm to pause the VM before calling
 * this function.  If accessing a memory file, this has no effect.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_resume_vm(
    vmi_instance_t vmi);

/**
 * Removes all entries from LibVMI's internal virtual to physical address
 * cache.  This is generally only useful if you believe that an entry in
 * the cache is incorrect, or out of date.
 *
 * @param[in] vmi LibVMI instance
 */
void vmi_v2pcache_flush(
    vmi_instance_t vmi);

/**
 * Adds one entry to LibVMI's internal virtual to physical address
 * cache.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] va Virtual address
 * @param[in] dtb Directory table base for \a va
 * @param[in] pa Physical address
 */
void vmi_v2pcache_add(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb,
    addr_t pa);

/**
 * Removes all entries from LibVMI's internal kernel symbol to virtual address
 * cache.  This is generally only useful if you believe that an entry in
 * the cache is incorrect, or out of date.
 *
 * @param[in] vmi LibVMI instance
 */
void vmi_symcache_flush(
    vmi_instance_t vmi);

/**
 * Adds one entry to LibVMI's internal symbol to virtual address
 * cache.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] base_addr Base address
 * @param[in] pid PID
 * @param[in] sym Symbol
 * @param[in] va Virtual address
 */
void vmi_symcache_add(
    vmi_instance_t vmi,
    addr_t base_addr,
    uint32_t pid,
    char *sym,
    addr_t va);

/**
 * Removes all entries from LibVMI's internal RVA to symbol
 * cache.  This is generally only useful if you believe that an entry in
 * the cache is incorrect, or out of date.
 *
 * @param[in] vmi LibVMI instance
 */
void vmi_rvacache_flush(
    vmi_instance_t vmi);

/**
 * Adds one entry to LibVMI's internal RVA to symbol
 * cache.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] base_addr Base address
 * @param[in] pid PID
 * @param[in] rva Relative virtual address
 * @param[in] sym Symbol
 */
void vmi_rvacache_add(
    vmi_instance_t vmi,
    addr_t base_addr,
    uint32_t pid,
    addr_t rva,
    char *sym);

/**
 * Removes all entries from LibVMI's internal pid to directory table base
 * cache.  This is generally only useful if you believe that an entry in
 * the cache is incorrect, or out of date.
 *
 * @param[in] vmi LibVMI instance
 */
void vmi_pidcache_flush(
    vmi_instance_t vmi);

/**
 * Adds one entry to LibVMI's internal pid to directory table base
 * cache.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] pid Process id
 * @param[in] dtb Directory table base
 */
void vmi_pidcache_add(
    vmi_instance_t vmi,
    int pid,
    addr_t dtb);

/*---------------------------------------------------------
 * Event management
 */
 
/* The types of events that can be requested of hypervisors with requisite
 *  features.
 */
typedef enum {
    VMI_EVENT_INVALID,
    VMI_EVENT_MEMORY,    /* Read/write/execute on a region of memory */
    VMI_EVENT_REGISTER,  /* Read/write of a specific register */
    VMI_EVENT_SINGLESTEP /* Instructions being executed on a set of VCPUs */
} vmi_event_type_t;

/* max number of vcpus we can set single step on at one time for a domain */
#define MAX_SINGLESTEP_VCPUS 32

/* Register operations used both for configuring type of register operations to
 *  monitor and also to determine the type of access causing an event to be
 *  recorded.
 */
typedef enum {
    VMI_REGACCESS_INVALID = 0,
    VMI_REGACCESS_N = (1 << 0),
    VMI_REGACCESS_R = (1 << 1),
    VMI_REGACCESS_W = (1 << 2),
    VMI_REGACCESS_RW = (VMI_REGACCESS_R | VMI_REGACCESS_W),
} vmi_reg_access_t;

/* Page permissions used both for configuring type of memory operations to
 *  monitor and also to determine the type of access causing an event to be
 *  recorded.
 */
typedef enum {
    VMI_MEMACCESS_INVALID    = 0,
    VMI_MEMACCESS_N          = (1 << 0),
    VMI_MEMACCESS_R          = (1 << 1),
    VMI_MEMACCESS_W          = (1 << 2),
    VMI_MEMACCESS_X          = (1 << 3),
    VMI_MEMACCESS_RW         = (VMI_MEMACCESS_R | VMI_MEMACCESS_W),
    VMI_MEMACCESS_RX         = (VMI_MEMACCESS_R | VMI_MEMACCESS_X),
    VMI_MEMACCESS_WX         = (VMI_MEMACCESS_W | VMI_MEMACCESS_X),
    VMI_MEMACCESS_RWX        = (VMI_MEMACCESS_R | VMI_MEMACCESS_W | VMI_MEMACCESS_X),
    VMI_MEMACCESS_X_ON_WRITE = (1 << 4)
} vmi_mem_access_t;

/* The level of granularity used in the configuration of a memory event.
 *  VMI_MEMEVENT_PAGE granularity delivers an event for any operation
 *   matching the access permission on the relevant page.
 *  VMI_MEMEVENT_BYTE granularity is more specific, deliving an event
 *   if an operation occurs involving the specific byte within a page
 */
typedef enum {
    VMI_MEMEVENT_INVALID,
    VMI_MEMEVENT_BYTE,
    VMI_MEMEVENT_PAGE
} vmi_memevent_granularity_t;

typedef struct {
    // IN
    registers_t reg; /* Register for which write event is configured.
                      * Hypervisors offering register events tend to
                      *  have a limited number available for monitoring.
                      * These registers tend to be those defined as 
                      * 'sensitive register instructions' by Popek and 
                      *  Goldberg, meaning that the registers trigger
                      *  a VMEXIT, trap, or equivalent.
                      */

    reg_t equal;     /* Event filter: callback triggers IFF register==value */

    reg_t mask;      /* Unused at the moment */

    int async:1;     /* IFF set to 1, events are delivered asynchronously and
                      *  without pausing the originating VCPU
                      * Default : 0 
                      *  (i.e., VCPU is paused at time of event delivery).
                      */

    int onchange:1;  /* IFF set to 1, events are only delivered if the written
                      *  value differs from the previously held value.
                      * Default : 0.
                      *  (i.e., All write events are delivered).
                      */

    vmi_reg_access_t in_access; /* Type of register event being monitored. 
                                 * Hypervisors offering register events tend
                                 *  to do so only for those that trigger a 
                                 *  VMEXIT or similar trap. This predominantly
                                 *  means that only write events are supported
                                 *  by the corresponding LibVMI driver
                                 */

    // OUT
    reg_t context;               /* MSR register operations only: holds the 
                                  *  specific MSR for which the event occurred.
                                  * Unused for other register event types.
                                  */

    reg_t value;                 /* Register value read or written */

    vmi_reg_access_t out_access; /* Type of register access that triggered
                                  * the event 
                                  */
} reg_event_t;

typedef struct {
    // IN
    vmi_memevent_granularity_t granularity; /* VMI_MEMEVENT_BYTE/PAGE */

    addr_t physical_address;                /* Physical address to set event on. 
                                             * With granularity of 
                                             *  VMI_MEMEVENT_PAGE, this can any
                                             *  byte on the target page.
                                             */

    uint64_t npages;                        /* Unsupported at the moment */

    vmi_mem_access_t in_access;             /* Page permissions used to trigger 
                                             *  memory events. See enum 
                                             *  definition for valid values
                                             */
    // OUT
    addr_t gla;                             /* Specific virtual address at which
                                             *  event occurred.
                                             */

    addr_t gfn;                             /* Page number at which event 
                                             *  occurred 
                                             */

    uint64_t offset;                        /* Offset in bytes (relative to
                                             *  page base) at which event
                                             *  occurred
                                             */

    vmi_mem_access_t out_access;            /* Type of page access that 
                                             *  caused event to be triggered.
                                             *  Typically a subset of in_access
                                             */
} mem_event_t;

typedef struct {
    addr_t gla;      /* The IP of the current instruction */
    addr_t gfn;      /* The physical page of the current instruction */
    uint32_t vcpus;  /* A packed int, with each bit representing the state of
                      *  the corresponding VCPU. E.g., if the 0th bit is 1,
                      *  single-stepping is enabled for the 0th VCPU via
                      *  whatever mechanism the hypervisor driver supports.
                      * See also helper macros SET_VCPU_SINGLESTEP,
                      *  UNSET_VCPU_SINGLESTEP, and CHECK_VCPU_SINGLESTEP
                      */
} single_step_event_t;

struct vmi_event;
typedef struct vmi_event vmi_event_t;

/* Event callback function prototype, taking two parameters:
 *  The vmi_instance_t passed by the library itself, and the vmi_event_t
 *   object provided by the library user.
 */
typedef void (*event_callback_t)(vmi_instance_t vmi, vmi_event_t *event);

/* The event structure used during configuration of events and their delivery */
struct vmi_event {
    vmi_event_type_t type;  /* The specific type of event */

    /* The specific event type structure (per event type above)
     *  "IN" members of the *_event_t are set by the library user during event
     *      registration to configure LibVMI and the hypervisor.
     *  "OUT" members are set by LibVMI upon observation of an event with 
     *      contextual information helpful to the callback.
     */
    union {
        reg_event_t reg_event;
        mem_event_t mem_event;
        single_step_event_t ss_event;
    };

    uint32_t vcpu_id; /* The VCPU relative to which the event occurred. */

    void * data;   /* An open-ended mechanism allowing a library user to 
                    *  associate external data to the event.
                    * Metadata assigned to this pointer at any time (prior to
                    *  or following registration) is delivered to the callback,
                    *  for each matching event. The callback is also free to 
                    *  modify in any way. The library user assumes all memory 
                    *  management for this referenced data.
                    */

    event_callback_t callback;  /* The callback function that is invoked
                                 *  when the relevant is observed
                                 */
};

/* Enables the correct bit for the given vcpu number x */
#define SET_VCPU_SINGLESTEP(ss_event, x) \
        ss_event.vcpus |= (1 << x)
        
/* Disables the correct bit for a given vcpu number x */ 
#define UNSET_VCPU_SINGLESTEP(ss_event, x) \
        ss_event.vcpus &= ~(1 << x)
        
/* Check to see if a vcpu number has single step enabled */
#define CHECK_VCPU_SINGLESTEP(ss_event, x) \
        (ss_event.vcpus) & (1 << x)

/**
 * Register to handle the event specified by the vmi_event object.
 *
 * Callback receives one event as input.
 * Callback is invoked while within the event listener loop, so
 *  actions taken by the callback must take into account that other 
 *  events may have been delivered and not yet processed. This is
 *  especially important when events have been configured in an
 *  asyncronous manner (i.e., events delivered are not necessarily
 *  in lockstep with the VM state).
 *
 * Memory management of the vmi_event_t being registered remains the 
 *  responsibility of the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] event Definition of event to monitor
 * @param[in] callback Function to call when the event occurs
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_register_event(
    vmi_instance_t vmi,
    vmi_event_t *event);

/**
 * Clear the event specified by the vmi_event_t object.
 *  
 * For memory events, this operation resets page permissions so that
 *  execution relative to related page or pages can continue without 
 *  further interaction.
 * For register and single-step events, this action disables monitoring
 *  of the given event type via the hypervisor driver.
 * In all cases, the event is removed from hashtables internal to LibVMI,
 *  but the memory related to the vmi_event_t is not freed. Memory management
 *  remains the responsibility of the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] event Definition of event to clear
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_clear_event(
    vmi_instance_t vmi,
    vmi_event_t *event);

/**
 * Return the pointer to the vmi_event_t if one is set on the given register.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] reg Register to check
 * @return vmi_event_t* or NULL if none found
 */
vmi_event_t *vmi_get_reg_event(
    vmi_instance_t vmi,
    registers_t reg);

/**
 * Return the pointer to the vmi_event_t if one is set on the given page.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] physical_address Physical address of byte/page to check
 * @param[in] granularity VMI_MEMEVENT_BYTE or VMI_MEMEVENT_PAGE
 * @return vmi_event_t* or NULL if none found
 */
vmi_event_t *vmi_get_mem_event(
    vmi_instance_t vmi,
    addr_t physical_address,
    vmi_memevent_granularity_t granularity);

/**
 * Listen for events until one occurs or a timeout.
 * If the timeout is given as 0, it will process leftover events
 * in the ring-buffer (if there are any).
 *
 * @param[in] vmi LibVMI instance
 * @param[in] timeout Number of ms.
 * @return VMI_FAILURE or VMI_SUCCESS (timeout w/ 0 events returns VMI_SUCCESS)
 */
status_t vmi_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout);

/**
 * Return the pointer to the vmi_event_t if one is set on the given vcpu.
 * 
 * @param[in] vmi LibVMI instance
 * @param[in] vcpu the vcpu to check
 * @return VMI_SUCCESS or VMI_FAILURE
 */
vmi_event_t *vmi_get_singlestep_event (vmi_instance_t vmi, 
    uint32_t vcpu);

/**
 * Disables the MTF single step flag from a vcpu as well as the
 * libvmi event object's bitfield position.
 * This does not disable single step for the whole domain.
 * 
 * @param[in] vmi LibVMI instance
 * @param[in] event the event to disable the vcpu on
 * @param[in] vcpu the vcpu to stop single stepping on
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_stop_single_step_vcpu(
    vmi_instance_t vmi,
    vmi_event_t* event,
    uint32_t vcpu);
    
/**
 * Cleans up any domain wide single step settings.
 * This should be called when the caller is completely
 * finished with single step, as it implicitly disables
 * single-step on all VM VCPUs.
 * 
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_shutdown_single_step(
    vmi_instance_t);

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif /* LIBVMI_H */

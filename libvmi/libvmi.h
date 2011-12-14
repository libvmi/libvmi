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

/* uncomment this and recompile to enable debug output */
//#define VMI_DEBUG

/* enable or disable the address cache (v2p, pid, etc) */
#define ENABLE_ADDRESS_CACHE 1

/* enable or disable the page cache */
#define ENABLE_PAGE_CACHE 1

#define VMI_AUTO (1 << 0)  /**< libvmi should detect what to monitor or view */
#define VMI_XEN  (1 << 1)  /**< libvmi is monitoring a Xen VM */
#define VMI_KVM  (1 << 2)  /**< libvmi is monitoring a KVM VM */
#define VMI_FILE (1 << 3)  /**< libvmi is viewing a file on disk */
#define VMI_INIT_PARTIAL  (1 << 16) /**< init enough to view physical addresses */
#define VMI_INIT_COMPLETE (1 << 17) /**< full initialization */

typedef enum status{
    VMI_SUCCESS,  /**< return value indicating success */
    VMI_FAILURE   /**< return value indicating failure */
} status_t;

typedef enum os{
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
typedef enum page_mode{
    VMI_PM_UNKNOWN, /**< page mode unknown */
    VMI_PM_LEGACY,  /**< 32-bit paging */
    VMI_PM_PAE,     /**< PAE paging */
    VMI_PM_IA32E    /**< IA-32e paging */
} page_mode_t;

typedef uint64_t reg_t;
typedef enum registers{
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

    TSC
} registers_t;

/* type def for forward compatibility with 64-bit guests */
typedef uint64_t addr_t;

// Windows' UNICODE_STRING structure
typedef struct _windows_unicode_string {
    uint16_t length;
    uint16_t maximum_length;
    // width of buffer could be incorrect depending on VM arch
    addr_t   buffer; // pointer (VA) to wide character buffer
} __attribute__((packed)) windows_unicode_string_t;

/**
 * @brief LibVMI Instance.
 *
 * This struct holds all of the relavent information for an instance of
 * LibVMI.  Each time a new domain is accessed, a new instance must
 * be created using the vmi_init function.  When you are done with an instance,
 * its resources can be freed using the vmi_destroy function.
 */
typedef struct vmi_instance * vmi_instance_t;

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
status_t vmi_init (vmi_instance_t *vmi, uint32_t flags, char *name);

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
status_t vmi_init_complete (vmi_instance_t *vmi, char *config);

/**
 * Destroys an instance by freeing memory and closing any open handles.
 *
 * @param[in] vmi Instance to destroy
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_destroy (vmi_instance_t vmi);

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
addr_t vmi_translate_kv2p(vmi_instance_t vmi, addr_t vaddr);

/**
 * Performs the translation from a user virtual address to a
 * physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Desired kernel virtual address to translate
 * @param[in] pid Process id for desired user address space
 * @return Physical address, or zero on error
 */
addr_t vmi_translate_uv2p(vmi_instance_t vmi, addr_t vaddr, int pid);

/**
 * Performs the translation from a kernel symbol to a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] symbol Desired kernel symbol to translate
 * @return Virtual address, or zero on error
 */
addr_t vmi_translate_ksym2v (vmi_instance_t vmi, char *symbol);

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
size_t vmi_read_ksym (vmi_instance_t vmi, char *sym, void *buf, size_t count);

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
size_t vmi_read_va (vmi_instance_t vmi, addr_t vaddr, int pid, void *buf, size_t count);

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
size_t vmi_read_pa (vmi_instance_t vmi, addr_t paddr, void *buf, size_t count);

/**
 * Reads 8 bits from memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_8_ksym (vmi_instance_t vmi, char *sym, uint8_t *value);

/**
 * Reads 16 bits from memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_16_ksym (vmi_instance_t vmi, char *sym, uint16_t *value);

/**
 * Reads 32 bits from memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_32_ksym (vmi_instance_t vmi, char *sym, uint32_t *value);

/**
 * Reads 64 bits from memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_64_ksym (vmi_instance_t vmi, char *sym, uint64_t *value);

/**
 * Reads an address from memory, given a kernel symbol.  The number of
 * bytes read is 8 for 64-bit systems and 4 for 32-bit systems.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_addr_ksym (vmi_instance_t vmi, char *sym, addr_t *value);

/**
 * Reads a null-terminated string from memory, starting at
 * the given kernel symbol.  The returned value must be
 * freed by the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol for memory location where string starts
 * @return String read from memory or NULL on error
 */
char *vmi_read_str_ksym (vmi_instance_t vmi, char *sym);

/**
 * Reads 8 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_8_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint8_t *value);

/**
 * Reads 16 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_16_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint16_t *value);

/**
 * Reads 32 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_32_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint32_t *value);

/**
 * Reads 64 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_64_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint64_t *value);

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
status_t vmi_read_addr_va (vmi_instance_t vmi, addr_t vaddr, int pid, addr_t *value);

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
char *vmi_read_str_va (vmi_instance_t vmi, addr_t vaddr, int pid);

/**
 * Reads a Windows Unicode string structure from memory, starting at the given
 * virtual address. The returned value must be freed by the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address of the UNICODE_STRING structure
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @return String read from memory or NULL on error
 */
wchar_t *vmi_read_win_ustr_va (vmi_instance_t vmi, addr_t vaddr, int pid);

/**
 * Reads a UTF-8 string from memory, starting at the given virtual
 * address. The returned value must be freed by the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address of the UTF-8 string
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @return String read from memory or NULL on error
 */
wchar_t *vmi_read_utf8_str_va (vmi_instance_t vmi, addr_t vaddr, int pid);






/**
 * Reads 8 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_8_pa (vmi_instance_t vmi, addr_t paddr, uint8_t *value);

/**
 * Reads 16 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_16_pa (vmi_instance_t vmi, addr_t paddr, uint16_t *value);

/**
 * Reads 32 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_32_pa (vmi_instance_t vmi, addr_t paddr, uint32_t *value);

/**
 * Reads 64 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_64_pa (vmi_instance_t vmi, addr_t paddr, uint64_t *value);

/**
 * Reads an address from memory, given a physical address.  The number of
 * bytes read is 8 for 64-bit systems and 4 for 32-bit systems.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_addr_pa (vmi_instance_t vmi, addr_t paddr, addr_t *value);

/**
 * Reads a nul terminated string from memory, starting at
 * the given physical address.  The returned value must be
 * freed by the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address for start of string
 * @return String read from memory or NULL on error
 */
char *vmi_read_str_pa (vmi_instance_t vmi, addr_t paddr);

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
size_t vmi_write_ksym (vmi_instance_t vmi, char *sym, void *buf, size_t count);

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
size_t vmi_write_va (vmi_instance_t vmi, addr_t vaddr, int pid, void *buf, size_t count);

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
size_t vmi_write_pa (vmi_instance_t vmi, addr_t paddr, void *buf, size_t count);

/**
 * Writes 8 bits to memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_8_ksym (vmi_instance_t vmi, char *sym, uint8_t *value);

/**
 * Writes 16 bits to memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_16_ksym (vmi_instance_t vmi, char *sym, uint16_t *value);

/**
 * Writes 32 bits to memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_32_ksym (vmi_instance_t vmi, char *sym, uint32_t *value);

/**
 * Writes 64 bits to memory, given a kernel symbol.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_64_ksym (vmi_instance_t vmi, char *sym, uint64_t *value);

/**
 * Writes 8 bits to memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to write to
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_8_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint8_t *value);

/**
 * Writes 16 bits to memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to write to
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_16_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint16_t *value);

/**
 * Writes 32 bits to memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to write to
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_32_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint32_t *value);

/**
 * Writes 64 bits to memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to write to
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_64_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint64_t *value);

/**
 * Writes 8 bits to memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_8_pa (vmi_instance_t vmi, addr_t paddr, uint8_t *value);

/**
 * Writes 16 bits to memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_16_pa (vmi_instance_t vmi, addr_t paddr, uint16_t *value);

/**
 * Writes 32 bits to memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_32_pa (vmi_instance_t vmi, addr_t paddr, uint32_t *value);

/**
 * Writes 64 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_64_pa (vmi_instance_t vmi, addr_t paddr, uint64_t *value);


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
void vmi_print_hex (unsigned char *data, unsigned long length);

/**
 * Prints out the hex and ascii version of a chunk of bytes. The
 * output is similar to what you would get with 'od -h' with the
 * additional ascii information on the right side of the display.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to use as starting address
 * @param[in] length The length (in bytes) of data to print
 */
void vmi_print_hex_ksym (vmi_instance_t vmi, char *sym, size_t length);

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
void vmi_print_hex_va (vmi_instance_t vmi, addr_t vaddr, int pid, size_t length);

/**
 * Prints out the hex and ascii version of a chunk of bytes. The
 * output is similar to what you would get with 'od -h' with the
 * additional ascii information on the right side of the display.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to use as starting address
 * @param[in] length The length (in bytes) of data to print
 */
void vmi_print_hex_pa (vmi_instance_t vmi, addr_t paddr, size_t length);


/*---------------------------------------------------------
 * Accessor functions from accessors.c
 */

/**
 * Gets the current access mode for LibVMI, which tells what 
 * resource is being using to access the memory (e.g., VMI_XEN,
 * VMI_KVM, or VMI_FILE).
 *
 * @param[in] vmi LibVMI instance
 * @return Access mode
 */
uint32_t vmi_get_access_mode (vmi_instance_t vmi);

/**
 * Gets the current page mode for LibVMI, which tells what 
 * type of address translation is in use (e.g., VMI_PM_LEGACY,
 * VMI_PM_PAE, or VMI_PM_IA32E).
 *
 * @param[in] vmi LibVMI instance
 * @return Page mode
 */
page_mode_t vmi_get_page_mode (vmi_instance_t vmi);

/**
 * Get the OS type that LibVMI is currently accessing.  This is
 * simple windows or linux (no version information).
 *
 * @param[in] vmi LibVMI instance
 * @return OS type
 */
os_t vmi_get_ostype (vmi_instance_t vmi);

/**
 * Get the version of Windows that LibVMI is currently accessing.  This is the
 * simple Windows version - no service pack or patch level is provided.
 *
 * @param[in] vmi LibVMI instance
 * @return Windows version
 */
win_ver_t vmi_get_winver (vmi_instance_t vmi);

/**
 * Get string represenatation of the version of Windows that LibVMI is currently accessing.
 *
 * @param[in] vmi LibVMI instance
 * @return string description of Windows version (do not free)
 */
const char * vmi_get_winver_str (vmi_instance_t vmi);

/**
 * Get the memory offset associated with the given offset_name.
 * Valid names include everything in the /etc/libvmi.conf file.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] offset_name String name for desired offset
 * @return The offset value
 */
unsigned long vmi_get_offset (vmi_instance_t vmi, char *offset_name);

/**
 * Gets the memory size of the guest or file that LibVMI is currently
 * accessing.  This is effectively the max physical address that you
 * can access in the system.
 *
 * @param[in] vmi LibVMI instance
 * @return Memory size
 */
unsigned long vmi_get_memsize (vmi_instance_t vmi);

/**
 * Gets the current value of a VCPU register.  This currently only
 * supports control registers.  When LibVMI is accessing a raw
 * memory file, this function will fail.
 *
 * @param[in] vmi LibVMI instance
 * @param[out] value Returned value from the register, only valid on VMI_SUCCESS
 * @param[in] reg The register to access
 * @param[in] vcpu The index of the VCPU to access, use 0 for single VCPU systems
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu);

/**
 * Pauses the VM.  Use vmi_resume_vm to resume the VM after pausing
 * it.  If accessing a memory file, this has no effect.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_pause_vm (vmi_instance_t vmi);

/**
 * Resumes the VM.  Use vmi_pause_vm to pause the VM before calling
 * this function.  If accessing a memory file, this has no effect.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_resume_vm (vmi_instance_t vmi);

#pragma GCC visibility pop
#endif /* LIBVMI_H */

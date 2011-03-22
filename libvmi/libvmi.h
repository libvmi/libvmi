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
    VMI_MODE_AUTO, /**< mode indicating that libvmi should detect what to monitor */
    VMI_MODE_XEN,  /**< mode indicating that we are monitoring a Xen VM */
    VMI_MODE_KVM,  /**< mode indicating that we are monitoring a KVM VM */
    VMI_MODE_FILE  /**< mode indicating that we are viewing a file on disk */
} mode_t;

typedef enum status{
    VMI_SUCCESS,  /**< return value indicating success */
    VMI_FAILURE   /**< return value indicating failure */
} status_t;

/**
 * Failure mode where LibVMI will exit with failure if there are
 * any problems found on startup.  This will provide for strict
 * checking of the configuration file parameters and the memory 
 * image itself.  If initialization completes successfully in this
 * mode, then you should then have full use of the LibVMI memory
 * access functionality (e.g., virtual, physical, and symbolic lookups).
 */
#define VMI_FAILHARD 0
/**
 * Failure mode where LibVMI will try to complete initialization
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
    CR0,
    CR1,
    CR2,
    CR3,
    CR4
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

/*---------------------------------------------------------
 * Initialization and Destruction functions from core.c
 */

/**
 * Initializes access to a specific VM given an ID.  All
 * calls to vmi_init must eventually call vmi_destroy.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per VM, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * @param[out] vmi Struct that holds instance information
 * @param[in] mode VMI_MODE_AUTO, VMI_MODE_XEN, or VMI_MODE_KVM
 * @param[in] id Unique id specifying the VM to view
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_id (vmi_instance_t *vmi, mode_t mode, unsigned long id);

/**
 * Initializes access to a specific VM or file given a name.  All
 * calls to vmi_init must eventually call vmi_destroy.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per VM or file, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * @param[out] vmi Struct that holds instance information
 * @param[in] mode VMI_MODE_AUTO, VMI_MODE_XEN, VMI_MODE_KVM, or VMI_MODE_FILE
 * @param[in] name Unique name specifying the VM or file to view
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_name (vmi_instance_t *vmi, mode_t mode, char *name);

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
uint32_t vmi_translate_kv2p(vmi_instance_t vmi, uint32_t vaddr);

/**
 * Performs the translation from a user virtual address to a
 * physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Desired kernel virtual address to translate
 * @param[in] pid Process id for desired user address space
 * @return Physical address, or zero on error
 */
uint32_t vmi_translate_uv2p(vmi_instance_t vmi, uint32_t vaddr, int pid);

/**
 * Performs the translation from a kernel symbol to a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] symbol Desired kernel symbol to translate
 * @return Virtual address, or zero on error
 */
uint32_t vmi_translate_ksym2v (vmi_instance_t vmi, char *symbol);

/*---------------------------------------------------------
 * Memory access functions from util.c
 */

/**
 * Reads \a count bytes from memory located at the kernel symbol \a symbol
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
size_t vmi_read_va (vmi_instance_t vmi, uint32_t vaddr, int pid, void *buf, size_t count);

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
size_t vmi_read_pa (vmi_instance_t vmi, uint32_t paddr, void *buf, size_t count);

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
 * Reads 8 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_8_va (vmi_instance_t vmi, uint32_t vaddr, int pid, uint8_t *value);

/**
 * Reads 16 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_16_va (vmi_instance_t vmi, uint32_t vaddr, int pid, uint16_t *value);

/**
 * Reads 32 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_32_va (vmi_instance_t vmi, uint32_t vaddr, int pid, uint32_t *value);

/**
 * Reads 64 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_64_va (vmi_instance_t vmi, uint32_t vaddr, int pid, uint64_t *value);

/**
 * Reads 8 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_8_pa (vmi_instance_t vmi, uint32_t paddr, uint8_t *value);

/**
 * Reads 16 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_16_pa (vmi_instance_t vmi, uint32_t paddr, uint16_t *value);

/**
 * Reads 32 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_32_pa (vmi_instance_t vmi, uint32_t paddr, uint32_t *value);

/**
 * Reads 64 bits from memory, given a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_64_pa (vmi_instance_t vmi, uint32_t paddr, uint64_t *value);

/*---------------------------------------------------------
 * Linux-specific functionality
 */

/**
 * Extracts information about the specified process' location in memory from
 * the task struct specified by @a pid.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] pid The PID for the task to read from
 * @param[out] taskaddr Information from the specified task struct
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_linux_get_taskaddr (vmi_instance_t vmi, int pid, vmi_linux_taskaddr_t *taskaddr);

/*---------------------------------------------------------
 * Windows-specific functionality
 */

/**
 * Extracts information from the PEB struct, which is located at the top of
 * the EPROCESS struct with the specified @a pid.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] pid The unique ID for the PEB to read from
 * @param[out] peb Information from the specified PEB
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_windows_get_peb (vmi_instance_t vmi, int pid, vmi_windows_peb_t *peb);

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
void vmi_print_hex (unsigned char *data, int length);

//TODO document the new functions listed below
os_t vmi_get_ostype (vmi_instance_t vmi);
unsigned long vmi_get_offset (vmi_instance_t vmi, char *offset_name);
unsigned long vmi_get_memsize (vmi_instance_t vmi);

#pragma GCC visibility pop
#endif /* LIBVMI_H */

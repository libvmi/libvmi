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
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#pragma GCC visibility push(default)

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#define VMI_INIT_DOMAINNAME (1u << 0) /**< initialize using domain name */

#define VMI_INIT_DOMAINID   (1u << 1) /**< initialize using domain id */

#define VMI_INIT_EVENTS     (1u << 2) /**< initialize events */

#define VMI_INIT_DOMAINUUID (1u << 3) /**< initialize using domain uuid */

#define VMI_INIT_DOMAINWATCH (1u << 4) /**< initialize using a domain watcher */

typedef enum vmi_mode {

    VMI_XEN, /**< libvmi is monitoring a Xen VM */

    VMI_KVM, /**< libvmi is monitoring a KVM VM */

    VMI_FILE, /**< libvmi is viewing a file on disk */

    VMI_BAREFLANK /** <libvmi is monitoring a Bareflank VM */
} vmi_mode_t;

typedef enum vmi_config {

    VMI_CONFIG_GLOBAL_FILE_ENTRY, /**< config in file provided */

    VMI_CONFIG_STRING,            /**< config string provided */

    VMI_CONFIG_GHASHTABLE,        /**< config GHashTable provided */

    VMI_CONFIG_JSON_PATH,         /**< config in json file at the location provided */
} vmi_config_t;

typedef enum status {

    VMI_SUCCESS,  /**< return value indicating success */

    VMI_FAILURE   /**< return value indicating failure */
} status_t;

typedef enum vmi_init_error {

    VMI_INIT_ERROR_NONE, /**< No error */

    VMI_INIT_ERROR_DRIVER_NOT_DETECTED, /**< Failed to auto-detect hypervisor */

    VMI_INIT_ERROR_DRIVER, /**< Failed to initialize hypervisor-driver */

    VMI_INIT_ERROR_VM_NOT_FOUND, /**< Failed to find the specified VM */

    VMI_INIT_ERROR_PAGING, /**< Failed to determine or initialize paging functions */

    VMI_INIT_ERROR_OS, /**< Failed to determine or initialize OS functions */

    VMI_INIT_ERROR_EVENTS, /**< Failed to initialize events */

    VMI_INIT_ERROR_NO_CONFIG, /**< No configuration was found for OS initialization */

    VMI_INIT_ERROR_NO_CONFIG_ENTRY, /**< Configuration contained no valid entry for VM */
} vmi_init_error_t;

typedef enum os {

    VMI_OS_UNKNOWN,  /**< OS type is unknown */

    VMI_OS_LINUX,    /**< OS type is Linux */

    VMI_OS_WINDOWS,  /**< OS type is Windows */

    VMI_OS_FREEBSD   /**< OS type is FreeBSD */
} os_t;

/**
 * Windows version enumeration.
 */
typedef enum win_ver {

    VMI_OS_WINDOWS_NONE,    /**< Not Windows */

    VMI_OS_WINDOWS_UNKNOWN, /**< Is Windows, not sure which */

    VMI_OS_WINDOWS_2000,

    VMI_OS_WINDOWS_XP,

    VMI_OS_WINDOWS_2003,

    VMI_OS_WINDOWS_VISTA,

    VMI_OS_WINDOWS_2008,

    VMI_OS_WINDOWS_7,

    VMI_OS_WINDOWS_8,

    VMI_OS_WINDOWS_10,
} win_ver_t;

typedef struct {
    win_ver_t version;
    uint16_t buildnumber;
    uint16_t major;
    uint16_t minor;
} win_build_info_t;

typedef uint32_t page_mode_t;
#define VMI_PM_NONE     0   /**< no page mode */
#define VMI_PM_UNKNOWN  1   /**< unknown paging mode */
#define VMI_PM_LEGACY   2   /**< x86 32-bit paging */
#define VMI_PM_PAE      3   /**< x86 PAE paging */
#define VMI_PM_IA32E    4   /**< x86 IA-32e paging */
#define VMI_PM_AARCH32  5   /**< ARM 32-bit paging */
#define VMI_PM_AARCH64  6   /**< ARM 64-bit paging */
#define VMI_PM_EPT_4L   7   /**< x86 4-level EPT */
#define VMI_PM_EPT_5L   8   /**< x86 5-level EPT */

/**
 * Allow the use of transition-pages when checking PTE.present bit. This is
 * a Windows-specific paging feature.
 */
#define VMI_PM_INITFLAG_TRANSITION_PAGES (1u << 0)

typedef enum page_size {

    VMI_PS_UNKNOWN  = 0ULL,         /**< page size unknown */

    VMI_PS_1KB      = 0x400ULL,     /**< 1KB */

    VMI_PS_4KB      = 0x1000ULL,    /**< 4KB */

    VMI_PS_16KB     = 0x4000ULL,    /**< 16KB */

    VMI_PS_64KB     = 0x10000ULL,   /**< 64KB */

    VMI_PS_1MB      = 0x100000ULL,  /**< 1MB */

    VMI_PS_2MB      = 0x200000ULL,  /**< 2MB */

    VMI_PS_4MB      = 0x400000ULL,  /**< 4MB */

    VMI_PS_16MB     = 0x1000000ULL, /**< 16MB */

    VMI_PS_32MB     = 0x2000000ULL, /**< 32MB */

    VMI_PS_512MB    = 0x20000000ULL,  /**< 512MB */

    VMI_PS_1GB      = 0x40000000ULL,  /**< 1GB */

} page_size_t;

#define VMI_INVALID_DOMID ~0ULL /**< invalid domain id */

/**
 * The types of initialization data that can be passed in
 */
typedef enum {
    VMI_INIT_DATA_XEN_EVTCHN, /**< Xen file descriptor */

    VMI_INIT_DATA_MEMMAP,    /**< memory_map_t pointer */

    VMI_INIT_DATA_KVMI_SOCKET     /**< kvmi socket path */
} vmi_init_data_type_t;

/**
 * Structures used to pass initialization data to LibVMI
 */
typedef struct {
    uint64_t type; /**< type (VMI_INIT_DATA_*) */
    void *data;    /**< the data being passed in */
} vmi_init_data_entry_t;

typedef struct {
    uint64_t count;  /**< number of entries */
    vmi_init_data_entry_t entry[]; /**< entry for each data being passed in */
} vmi_init_data_t;

/**
 * Structure to define valid memory ranges within the target.
 *
 * On x86 this can be used to pass the E820 or EFI memory map
 * to LibVMI so that accesses to invalid ranges can be skipped.
 */
typedef struct {
    uint64_t count;
    uint64_t range[][2]; /**< start and end address of valid memory ranges */
} memory_map_t;

typedef uint64_t reg_t;

/**
 * The following definitions are used where the API defines
 * either reg_t or registers_t.
 *
 * x86_* registers
 */
#define EAX              0
#define EBX              1
#define ECX              2
#define EDX              3
#define EBP              4
#define ESI              5
#define EDI              6
#define ESP              7

#define EIP              8
#define EFLAGS           9

#define RAX        EAX
#define RBX        EBX
#define RCX        ECX
#define RDX        EDX
#define RBP        EBP
#define RSI        ESI
#define RDI        EDI
#define RSP        ESP

#define RIP        EIP
#define RFLAGS     EFLAGS

#define R8               10
#define R9               11
#define R10              12
#define R11              13
#define R12              14
#define R13              15
#define R14              16
#define R15              17

#define CR0              18
#define CR2              19
#define CR3              20
#define CR4              21
#define XCR0             22

#define DR0              23
#define DR1              24
#define DR2              25
#define DR3              26
#define DR6              27
#define DR7              28

#define CS_SEL           29
#define DS_SEL           30
#define ES_SEL           31
#define FS_SEL           32
#define GS_SEL           33
#define SS_SEL           34
#define TR_SEL           35
#define LDTR_SEL         36

#define CS_LIMIT         37
#define DS_LIMIT         38
#define ES_LIMIT         39
#define FS_LIMIT         40
#define GS_LIMIT         41
#define SS_LIMIT         42
#define TR_LIMIT         43
#define LDTR_LIMIT       44
#define IDTR_LIMIT       45
#define GDTR_LIMIT       46

#define CS_BASE          47
#define DS_BASE          48
#define ES_BASE          49
#define FS_BASE          50
#define GS_BASE          51
#define SS_BASE          52
#define TR_BASE          53
#define LDTR_BASE        54
#define IDTR_BASE        55
#define GDTR_BASE        56

#define CS_ARBYTES       57
#define DS_ARBYTES       58
#define ES_ARBYTES       59
#define FS_ARBYTES       60
#define GS_ARBYTES       61
#define SS_ARBYTES       62
#define TR_ARBYTES       63
#define LDTR_ARBYTES     64

#define SYSENTER_CS      65
#define SYSENTER_ESP     66
#define SYSENTER_EIP     67

#define SHADOW_GS        68
#define TSC              69

#define MSR_FLAGS        70
#define MSR_LSTAR        71
#define MSR_CSTAR        72
#define MSR_SYSCALL_MASK 73
#define MSR_EFER         74
#define MSR_TSC_AUX      75

#define MSR_STAR                    119
#define MSR_SHADOW_GS_BASE          120
#define MSR_MTRRfix64K_00000        121
#define MSR_MTRRfix16K_80000        122
#define MSR_MTRRfix16K_A0000        123
#define MSR_MTRRfix4K_C0000         124
#define MSR_MTRRfix4K_C8000         125
#define MSR_MTRRfix4K_D0000         126
#define MSR_MTRRfix4K_D8000         127
#define MSR_MTRRfix4K_E0000         128
#define MSR_MTRRfix4K_E8000         129
#define MSR_MTRRfix4K_F0000         130
#define MSR_MTRRfix4K_F8000         131
#define MSR_MTRRdefType             132
#define MSR_IA32_MC0_CTL            133
#define MSR_IA32_MC0_STATUS         134
#define MSR_IA32_MC0_ADDR           135
#define MSR_IA32_MC0_MISC           136
#define MSR_IA32_MC1_CTL            137
#define MSR_IA32_MC0_CTL2           138
#define MSR_AMD_PATCHLEVEL          139
#define MSR_AMD64_TSC_RATIO         140
#define MSR_IA32_P5_MC_ADDR         141
#define MSR_IA32_P5_MC_TYPE         142
#define MSR_IA32_TSC                143
#define MSR_IA32_PLATFORM_ID        144
#define MSR_IA32_EBL_CR_POWERON     145
#define MSR_IA32_EBC_FREQUENCY_ID   146
#define MSR_IA32_FEATURE_CONTROL    147
#define MSR_IA32_SYSENTER_CS        148
#define MSR_IA32_SYSENTER_ESP       149
#define MSR_IA32_SYSENTER_EIP       150
#define MSR_IA32_MISC_ENABLE        151
#define MSR_HYPERVISOR              152

/**
 * Special generic case for specifying arbitrary MSRs
 */
#define MSR_ANY                     153
#define MSR_UNDEFINED MSR_ANY       /* deprecated */

/**
 * Special generic case for handling MSRs, given their understandably
 * generic treatment for events in Xen and elsewhere. Not relevant for
 * vCPU get/set of register data.
 */
#define MSR_ALL          76

/**
 * ARM32 Registers
 */
#define SCTLR            77
#define CPSR             78

#define TTBCR            79
#define TTBR0            80
#define TTBR1            81

#define R0               82
#define R1               83
#define R2               84
#define R3               85
#define R4               86
#define R5               87
#define R6               88
#define R7               89

/* R8-R15 already defined */

#define SPSR_SVC         90
#define SPSR_FIQ         91
#define SPSR_IRQ         92
#define SPSR_UND         93
#define SPSR_ABT         94

#define LR_IRQ           95
#define SP_IRQ           96

#define LR_SVC           97
#define SP_SVC           98

#define LR_ABT           99
#define SP_ABT           100

#define LR_UND           101
#define SP_UND           102

#define R8_FIQ           103
#define R9_FIQ           104
#define R10_FIQ          105
#define R11_FIQ          106
#define R12_FIQ          107

#define SP_FIQ           108
#define LR_FIQ           109

#define PC               118

/**
 * Compatibility naming
 */
#define SP_USR      R13
#define LR_USR      R14
#define PC32        PC

/**
 * ARM64 register
 */
#define SP_EL0           110
#define SP_EL1           111
#define ELR_EL1          112

/**
 * Many ARM64 registers are architecturally mapped over ARM32 registers
 */
#define X0          R0
#define X1          R1
#define X2          R2
#define X3          R3
#define X4          R4
#define X5          R5
#define X6          R6
#define X7          R7
#define X8          R8
#define X9          R9
#define X10         R10
#define X11         R11
#define X12         R12
#define X13         R13
#define X14         R14
#define X15         R15
#define X16         LR_IRQ
#define X17         SP_IRQ
#define X18         LR_SVC
#define X19         SP_SVC
#define X20         LR_ABT
#define X21         SP_ABT
#define X22         LR_UND
#define X23         SP_UND
#define X24         R8_FIQ
#define X25         R9_FIQ
#define X26         R10_FIQ
#define X27         R11_FIQ
#define X28         R12_FIQ
#define X29         SP_FIQ
#define X30         LR_FIQ

#define PC64        PC
#define SPSR_EL1    SPSR_SVC
#define TCR_EL1     TTBCR

typedef struct x86_mtrr_regs {
    uint64_t msr_pat_cr;
    uint64_t msr_mtrr_cap;
} mtrr_regs_t;

/*
 * The format used for x86 segment flags by LibVMI.
 */
typedef struct x86_segment_flags {
    uint16_t type:4; // 0-3
    uint16_t s:   1; // 4
    uint16_t dpl: 2; // 5-6
    uint16_t p:   1; // 7
    uint16_t avl: 1; // 8
    uint16_t l:   1; // 9
    uint16_t db:  1; // 10
    uint16_t g:   1; // 11
    uint16_t pad: 4; // 12-15
    uint16_t pad2;   // 16-31
    uint32_t pad3;   // 32-63
} x86_segment_flags_t;

/*
 * Commonly used x86 registers
 */
typedef struct x86_regs {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t dr6;
    uint64_t dr7;
    uint64_t rip;
    uint64_t cr0;
    uint64_t cr2;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t sysenter_cs;
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;
    uint64_t msr_efer;
    uint64_t msr_star;
    uint64_t msr_lstar;
    uint64_t msr_pat;
    uint64_t msr_cstar;

    uint64_t fs_base;
    uint64_t fs_limit;
    uint64_t fs_sel;
    union {
        uint64_t fs_arbytes;
        x86_segment_flags_t fs_flags;
    };
    uint64_t gs_base;
    uint64_t gs_limit;
    uint64_t gs_sel;
    union {
        uint64_t gs_arbytes;
        x86_segment_flags_t gs_flags;
    };
    uint64_t cs_base;
    uint64_t cs_limit;
    uint64_t cs_sel;
    union {
        uint64_t cs_arbytes;
        x86_segment_flags_t cs_flags;
    };
    uint64_t ss_base;
    uint64_t ss_limit;
    uint64_t ss_sel;
    union {
        uint64_t ss_arbytes;
        x86_segment_flags_t ss_flags;
    };
    uint64_t ds_base;
    uint64_t ds_limit;
    uint64_t ds_sel;
    union {
        uint64_t ds_arbytes;
        x86_segment_flags_t ds_flags;
    };
    uint64_t es_base;
    uint64_t es_limit;
    uint64_t es_sel;
    union {
        uint64_t es_arbytes;
        x86_segment_flags_t es_flags;
    };
    uint64_t tr_base;
    uint64_t tr_limit;
    uint64_t tr_sel;
    union {
        uint64_t tr_arbytes;
        x86_segment_flags_t tr_flags;
    };
    uint64_t ldt_base;
    uint64_t ldt_limit;
    uint64_t ldt_sel;
    union {
        uint64_t ldt_arbytes;
        x86_segment_flags_t ldt_flags;
    };

    uint64_t shadow_gs;
    uint64_t idtr_base;
    uint64_t idtr_limit;
    uint64_t gdtr_base;
    uint64_t gdtr_limit;
    uint64_t npt_base;
    uint64_t vmtrace_pos;
} x86_registers_t;

typedef struct arm_registers {
    uint64_t ttbr0;
    uint64_t ttbr1;
    uint64_t ttbcr;
    uint64_t pc;
    uint32_t cpsr;
    uint32_t _pad;
} arm_registers_t;

typedef struct registers {
    union {
        x86_registers_t x86;
        arm_registers_t arm;
    };
} registers_t;

typedef struct xsave_area {
    char fpu_sse[512];
    uint64_t xstate_bv;         /* Updated by XRSTOR */
    uint64_t xcomp_bv;          /* Updated by XRSTOR{C,S} */
} xsave_area_t;

/**
 * typedef for forward compatibility with 64-bit guests
 */
typedef uint64_t addr_t;

/**
 * type def for consistent pid_t usage
 */
typedef int32_t vmi_pid_t;

/**
 * Struct for holding page lookup information
 */
typedef struct page_info {
    addr_t vaddr;       /**< virtual address */
    addr_t paddr;       /**< physical address */
    addr_t naddr;       /**< nested address */

    page_size_t size;   /**< page size (VMI_PS_*) */
    page_size_t nsize;  /**< nested page size (VMI_PS_*) */

    addr_t pt;          /**< pagetable used for translation */
    page_mode_t pm;     /**< page mode user for translation */

    addr_t npt;         /**< nested pagetable used for translation */
    page_mode_t npm;    /**< nested page mode user for translation */

    union {
        struct {
            addr_t pte_location;
            addr_t pte_value;
            addr_t pgd_location;
            addr_t pgd_value;
        } x86_legacy;

        struct {
            addr_t pte_location;
            addr_t pte_value;
            addr_t pgd_location;
            addr_t pgd_value;
            addr_t pdpe_location;
            addr_t pdpe_value;
        } x86_pae;

        struct {
            addr_t pte_location;
            addr_t pte_value;
            addr_t pgd_location;
            addr_t pgd_value;
            addr_t pdpte_location;
            addr_t pdpte_value;
            addr_t pml4e_location;
            addr_t pml4e_value;
        } x86_ia32e;

        struct {
            uint32_t fld_location;
            uint32_t fld_value;
            uint32_t sld_location;
            uint32_t sld_value;
        } arm_aarch32;

        struct {
            uint64_t zld_location;
            uint64_t zld_value;
            uint64_t fld_location;
            uint64_t fld_value;
            uint64_t sld_location;
            uint64_t sld_value;
            uint64_t tld_location;
            uint64_t tld_value;
        } arm_aarch64;
    };
} page_info_t;

/**
 * Supported architectures by LibVMI
 */
typedef enum arch {
    VMI_ARCH_UNKNOWN,        /**< Unknown architecture */
    VMI_ARCH_X86,            /**< x86 32-bit architecture */
    VMI_ARCH_X86_64,         /**< x86 64-bit architecture */
    VMI_ARCH_ARM32,          /**< ARM 32-bit architecture */
    VMI_ARCH_ARM64           /**< ARM 64-bit architecture */
} vmi_arch_t;

/**
 * Available translation mechanism for v2p conversion.
 */
typedef uint32_t translation_mechanism_t;
#define VMI_TM_NONE              0 /**< No translation is required, address is physical address */
#define VMI_TM_PROCESS_DTB       1 /**< Translate addr via specified pagetable (aka. directory table base). */
#define VMI_TM_PROCESS_PT        1 /**< Translate addr via specified pagetable. */
#define VMI_TM_PROCESS_PID       2 /**< Translate addr by finding process first to use its DTB. */
#define VMI_TM_KERNEL_SYMBOL     3 /**< Find virtual address of kernel symbol and translate it via kernel DTB. */

/**
 * Structure to use as input to accessor functions
 * specifying how the access should be performed.
 * Must specify ABI version.
 */
#define ACCESS_CONTEXT_VERSION 0x1u
#define ACCESS_CONTEXT(C, ...)                  \
    access_context_t C = {                      \
        .version = ACCESS_CONTEXT_VERSION,      \
        __VA_ARGS__                             \
    }

typedef struct {
    uint32_t version;   /**< ABI struct version */
    uint32_t _pad;

    union {
        page_mode_t pm; /**< paging mode to use for translation */
        page_mode_t page_mode; /**< paging mode to use for translation */
    };
    union {
        page_mode_t npm; /**< paging mode to use for nested translation */
        page_mode_t nested_page_mode; /**< paging mode to use for nested translation */
    };
    union {
        addr_t npt; /**< specify iff using nested translation */
        addr_t nested_page_table; /**< specify iff using nested translation */
    };
    union {
        translation_mechanism_t tm; /**< method to use for translation */
        translation_mechanism_t translate_mechanism; /**< method to use for translation */
    };

    uint32_t _pad2;

    union {
        struct {
            addr_t addr; /**< address to translate */

            union {
                addr_t pt;         /**< iff VMI_TM_PROCESS_DTB/PT */
                addr_t page_table; /**< iff VMI_TM_PROCESS_DTB/PT */
                addr_t dtb;        /**< iff VMI_TM_PROCESS_DTB/PT */
                vmi_pid_t pid;     /**< iff VMI_TM_PROCESS_PID */
            };
        };

        /* VMI_TM_KERNEL_SYMBOL */
        const char *ksym; /**< kernel symbol to translate  */
    };
} access_context_t;

/**
 * Macro to test bitfield values (up to 64-bits)
 */
#define VMI_GET_BIT(reg, bit) (!!(reg & (1ULL<<bit)))

/**
 * Macro to compute bitfield masks (up to 64-bits)
 */
#define VMI_BIT_MASK(a, b) (((unsigned long long) -1 >> (63 - (b))) & ~((1ULL << (a)) - 1))

/**
 * Generic representation of Unicode string to be used within libvmi
 */
typedef struct _ustring {

    size_t length;         /**< byte count of contents */

    uint8_t *contents;     /**< pointer to byte array holding string */

    const char *encoding;  /**< holds iconv-compatible encoding of contents; do not free */
} unicode_string_t;

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
 * Initializes access to a specific VM or file given a name or an ID.  All
 * calls to vmi_init must eventually call vmi_destroy.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per VM or file, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * When this function returns VMI_SUCCESS, you will have access to the physical
 * memory of the target VM, as well as vCPU register functions. If you need
 * access to virtual-to-physical translation or OS specific information,
 * you will further need to call the appropriate init functions. Alternatively,
 * you can use vmi_init_complete to initialize access to all LibVMI functions.
 *
 * @param[out] vmi Struct that holds instance information
 * @param[in] mode Specifying the hypervisor mode to init
 *                 You can call vmi_get_access_mode prior to calling vmi_init to
 *                 automatically determine this.
 * @param[in] domain Unique name or id specifying the VM or file to view
 *                   Need to specify whether this is a domainname or domainid
 *                   by setting either VMI_INIT_DOMAINNAME or VMI_INIT_DOMAINID
 *                   on init_flags.
 * @param[in] init_flags Init flags to specify the domain input (name or id) and
 *                       to initialize further LibVMI features, such as events.
 *                       See VMI_INIT_* declarations above.
 * @param[in] init_data In case initialization requires additional information
 *                      for a given hypervisor, it can be provided via this
 *                      input.
 * @param[out] error Optional. If not NULL and the function returns VMI_FAILURE,
 *                   this will specify the stage at which initialization failed.
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init(
    vmi_instance_t *vmi,
    vmi_mode_t mode,
    const void *domain,
    uint64_t init_flags,
    vmi_init_data_t *init_data,
    vmi_init_error_t *error) NOEXCEPT;

/**
 * Initializes access to a specific VM or file given a name or an ID.  All
 * calls to vmi_init_complete must eventually call vmi_destroy.
 *
 * This is a costly funtion in terms of the time needed to execute.
 * You should call this function only once per VM or file, and then use the
 * resulting instance when calling any of the other library functions.
 *
 * When this function returns VMI_SUCCESS, you will have access to the physical
 * memory of the target VM, accessing vCPU registers, virtual-to-physcal
 * translation as well as OS specific functions.
 *
 * @param[out] vmi Struct that holds instance information
 * @param[in] domain Unique name or id specifying the VM or file to view
 *                   Need to specify whether this is a domainname or domainid
 *                   by setting either VMI_INIT_DOMAINNAME or VMI_INIT_DOMAINID
 *                   on init_flags.
 * @param[in] init_flags Additional flags to initialize
 *                       See VMI_INIT_* declarations above.
 * @param[in] init_data In case initialization requires additional information
 *                      for a given hypervisor, it can be provided via this
 *                      input.
 * @param[in] config_mode The type of OS configuration that is provided.
 * @param[in] config Configuration is passed directly to LibVMI (ie. in a string
 *                   or in a GHashTable) or NULL of global config file is used.
 * @param[out] error Optional. If not NULL and the function returns VMI_FAILURE,
 *                   this will specify the stage at which initialization failed.
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_init_complete(
    vmi_instance_t *vmi,
    const void *domain,
    uint64_t init_flags,
    vmi_init_data_t *init_data,
    vmi_config_t config_mode,
    void *config,
    vmi_init_error_t *error) NOEXCEPT;

/**
 * Initialize or reinitialize the paging specific functionality of LibVMI
 * required for virtual-to-physical translation.
 *
 * Note: this function is designed only for live VMs (ie. VMI_XEN or VMI_KVM).
 *  and will not work in VMI_FILE mode as that requires OS-specific heuristics.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paging_flags Additional flags to configure paging using
                           VMI_PM_INITFLAG_* values.
 * @return The page mode that was initialized, or VMI_PM_UNKNOWN.
 */
page_mode_t vmi_init_paging(
    vmi_instance_t vmi,
    uint64_t flags) NOEXCEPT;

/**
 * Initialize the OS specific functionality of LibVMI required for functions
 * such as vmi_*_ksym. If the user hasn't called vmi_init_paging yet, this
 * function will do that automatically.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] config_mode The type of OS configuration that is provided.
 * @param[in] config Configuration is passed directly to LibVMI (ie. in a string
 *                   or in a GHashTable) or NULL if global config file is used.
 * @param[out] error Optional. If not NULL and the function returns VMI_OS_UNKNOWN,
 *                   this will specify the stage at which initialization failed.
 * @return VMI_OS_UNKNOWN when the configuration didn't work for the VM, otherwise
 *         the OS type that has been initialized (ie. VMI_OS_WINDOWS or
 *         VMI_OS_LINUX).
 */
os_t vmi_init_os(
    vmi_instance_t vmi,
    vmi_config_t config_mode,
    void *config,
    vmi_init_error_t *error) NOEXCEPT;

/**
 * Destroys an instance by freeing memory and closing any open handles.
 *
 * @param[in] vmi Instance to destroy
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_destroy(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Obtain the library arch mode that was used for compiling.
 *
 * @param[in] vmi LibVMI instance
 * @return The architecture of the library
 */
vmi_arch_t vmi_get_library_arch(void) NOEXCEPT;

/*---------------------------------------------------------
 * Memory translation functions from memory.c
 */

/**
 * Performs the translation from a kernel virtual address to a
 * physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Desired kernel virtual address to translate
 * @param[out] paddr Physical address
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_translate_kv2p(
    vmi_instance_t vmi,
    addr_t vaddr,
    addr_t *paddr) NOEXCEPT;

/**
 * Performs the translation from a user virtual address to a
 * physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Desired kernel virtual address to translate
 * @param[in] pid Process id for desired user address space
 * @param[out] paddr Physical address
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_translate_uv2p(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    addr_t *paddr) NOEXCEPT;

/**
 * Performs the translation from a kernel symbol to a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] symbol Desired kernel symbol to translate
 * @param[out] paddr Virtual address
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_translate_ksym2v(
    vmi_instance_t vmi,
    const char *symbol,
    addr_t *vaddr) NOEXCEPT;

/**
 * Performs the translation from a symbol to a virtual address.
 * On Windows this function walks the PE export table.
 * Linux is unimplemented at this time.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context (beginning of PE header in Windows)
 * @param[in] symbol Desired symbol to translate
 * @param[out] vaddr Virtual address
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_translate_sym2v(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    const char *symbol,
    addr_t *vaddr) NOEXCEPT;

/**
 * Performs the translation from an RVA to a symbol
 * On Windows this function walks the PE export table.
 * Only the first matching symbol of System.map is returned.
 * ELF Headers are not supported.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context (beginning of PE header in Windows)
 * @param[in] rva RVA to translate
 * @return Symbol, or NULL on error
 */
const char* vmi_translate_v2sym(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t rva) NOEXCEPT;

/**
 * Performs the translation from VA to a symbol for Linux with KASLR offset
 * Windows is not supported at this moment
 * Only the first matching symbol of System.map is returned.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[in] va VA to translate
 * @return Symbol, or NULL on error
 */
const char* vmi_translate_v2ksym(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t va) NOEXCEPT;

/**
 * Given a pid, this function returns the virtual address of the
 * directory table base for this process' address space.  This value
 * is effectively what would be in the CR3 register while this process
 * is running.
 *
 * Note: this function uses OS internal linked-lists to find a match but
 * these lists are not guaranteed to be complete and accurate. Use of
 * this function is discouraged when using events.
 *
 * Note: Use of this function is discouraged with events.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] pid Desired process id to lookup
 * @param[out] dtb The directory table base virtual address for a pid
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_pid_to_dtb(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t *dtb) NOEXCEPT;

/**
 * Given a dtb, this function returns the PID corresponding to the
 * virtual address of the directory table base.
 * This function does NOT implement caching as to avoid false mappings.
 *
 * Note: this function uses OS internal linked-lists to find a match but
 * these lists are not guaranteed to be complete and accurate. Use of
 * this function is discouraged when using events.
 *
 * Note: On Linux certain PIDs don't have their own dtb (task->mm)
 * and rather re-use other process' dtb (task->active_mm). In such case
 * the PID returned by this function will be that of the "owning" process.
 *
 * Note: Use of this function is discouraged with events.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] dtb Desired dtb to lookup
 * @param[out] pid The PID corresponding to the dtb
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_dtb_to_pid(
    vmi_instance_t vmi,
    addr_t dtb,
    vmi_pid_t *pid) NOEXCEPT;

/**
 * Translates a virtual address to a physical address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] pt address of the relevant pagetable
 * @param[in] vaddr virtual address to translate via dtb
 * @param[out] paddr Physical address
 * @return VMI_SUCCESS or VMI_FAILURE
 */

status_t vmi_pagetable_lookup (
    vmi_instance_t vmi,
    addr_t pt,
    addr_t vaddr,
    addr_t *paddr) NOEXCEPT;

/**
 * Gets the physical address and page size of the VA
 * as well as the addresses of other paging related structures
 * depending on the page mode of the VM.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] pt address of the relevant pagetable
 * @param[in] vaddr virtual address to translate via dtb
 * @param[in,out] info Pointer to the struct to store the lookup information in
 * @return VMI_SUCCESS or VMI_FAILURE of the VA is invalid
 */
status_t vmi_pagetable_lookup_extended(
    vmi_instance_t vmi,
    addr_t pt,
    addr_t vaddr,
    page_info_t *info) NOEXCEPT;

/**
 * Translates a virtual address to a physical address, supporting nested
 * pagetables (ie. EPT). Can be called with npm set to VMI_PM_NONE, in which
 * case this function is equivalent to vmi_pagetable_lookup.
 *
 * To perform only nested pagetable lookup of an l2 guest paddr use pt and pm
 * with the nested pagetable address and mode.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] npt address of the nested pagetable
 * @param[in] npm page mode to use for lookup in nested pagetable
 * @param[in] pt address of the relevant pagetable
 * @param[in] pm page mode to use for lookup.
 * @param[in] vaddr virtual address to translate via dtb
 * @param[out] paddr Guest physical address (l2)
                     value is set to ~0ull if npm is set and translation was in
                     the v2p cache
 * @param[out] naddr Guest nested physical address (l1) if npm is set
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_nested_pagetable_lookup (
    vmi_instance_t vmi,
    addr_t npt,
    page_mode_t npm,
    addr_t pt,
    page_mode_t pm,
    addr_t vaddr,
    addr_t *paddr,
    addr_t *naddr) NOEXCEPT;

/**
 * Gets the physical address and page size of the VA
 * as well as the addresses of other paging related structures
 * depending on the page mode(s), supprting nested pagetables (ie. EPT).
 *
 * @param[in] vmi LibVMI instance
 * @param[in] npt address of the nested pagetable
 * @param[in] npm page mode to use for lookup in nested pagetable
 * @param[in] pt address of the relevant pagetable
 * @param[in] pm page mode to use for lookup
 * @param[in] vaddr virtual address to translate via dtb
 * @param[in,out] info Pointer to the struct to store the lookup information in
 * @return VMI_SUCCESS or VMI_FAILURE of the VA is invalid
 */
status_t vmi_nested_pagetable_lookup_extended(
    vmi_instance_t vmi,
    addr_t npt,
    page_mode_t npm,
    addr_t pt,
    page_mode_t pm,
    addr_t vaddr,
    page_info_t *info) NOEXCEPT;

/*---------------------------------------------------------
 * Memory access functions
 */

/**
 * Reads count bytes from memory and stores the output in a buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[in] count The number of bytes to read
 * @param[out] buf The data read from memory
 * @param[out] bytes_read Optional. The number of bytes read
 * @return VMI_SUCCESS if read is complete, VMI_FAILURE otherwise
 */
status_t vmi_read(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t count,
    void *buf,
    size_t *bytes_read) NOEXCEPT;

/**
 * Reads 8 bits from memory.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_8(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint8_t * value) NOEXCEPT;

/**
 * Reads 16 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_16(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint16_t * value) NOEXCEPT;

/**
 * Reads 32 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_32(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint32_t * value) NOEXCEPT;

/**
 * Reads 64 bits from memory, given a virtual address.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_64(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint64_t * value) NOEXCEPT;

/**
 * Reads an address from memory, given a virtual address.  The number of
 * bytes read is 8 for 64-bit systems and 4 for 32-bit systems.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[out] value The value read from memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_read_addr(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t *value) NOEXCEPT;

/**
 * Reads a null terminated string from memory, starting at
 * the given virtual address.  The returned value must be
 * freed by the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @return String read from memory or NULL on error
 */
char *vmi_read_str(
    vmi_instance_t vmi,
    const access_context_t *ctx) NOEXCEPT;

/**
 * Reads a Unicode string from the given address. If the guest is running
 * Windows, a UNICODE_STRING struct is read. Linux is not yet
 * supported. The returned value must be freed by the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @return String read from memory or NULL on error; this function
 *         will set the encoding field.
 */
unicode_string_t *vmi_read_unicode_str(
    vmi_instance_t vmi,
    const access_context_t *ctx) NOEXCEPT;

/**
 * Reads a Unicode string from the given address using the specified page mode.
 * This is needed for introspecting Windows-on-Windows (WoW) processes that
 * are 32-bit code running on 64-bit OS.
 * If the guest is running Windows, a UNICODE_STRING struct is read.
 *  Linux is not yet supported. The returned value must be freed by the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[in] mode Memory page mode
 * @return String read from memory or NULL on error; this function
 *         will set the encoding field.
 */
unicode_string_t *vmi_read_unicode_str_pm(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    page_mode_t mode ) NOEXCEPT;

/**
 * Reads count bytes from memory located at the kernel symbol sym
 * and stores the output in a buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to read from
 * @param[in] count The number of bytes to read
 * @param[out] buf The data read from memory
 * @param[out] bytes_read Optional. The number of bytes read
 * @return VMI_SUCCESS if read is complete, VMI_FAILURE otherwise
 */
status_t vmi_read_ksym(
    vmi_instance_t vmi,
    const char *sym,
    size_t count,
    void *buf,
    size_t *bytes_read
) NOEXCEPT;

/**
 * Reads count bytes from memory located at the virtual address vaddr
 * and stores the output in buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to read from
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] count The number of bytes to read
 * @param[out] buf The data read from memory
 * @param[out] bytes_read Optional. The number of bytes read
 * @return VMI_SUCCESS if read is complete, VMI_FAILURE otherwise
 */
status_t vmi_read_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    size_t count,
    void *buf,
    size_t *bytes_read
) NOEXCEPT;

/**
 * Maps num_pages of the guest's virtual memory into host, starting at the provided vaddr.
 * Each page will have it's own pointer in access_ptrs output array. Be aware that
 * not all virtual pages may be allocated and in such case, the corresponding array item
 * will be set to NULL. Remember to call munmap() on each array item afterwards.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[in] num_pages Number of guest pages to be mapped (starting from ctx.addr)
 * @param[out] access_ptrs Output array of size [num_pages] containing pointers to the respective guest's pages
 */
status_t vmi_mmap_guest(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t num_pages,
    void **access_ptrs
) NOEXCEPT;

/**
 * Reads count bytes from memory located at the physical address paddr
 * and stores the output in a buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to read from
 * @param[in] count The number of bytes to read
 * @param[out] buf The data read from memory
 * @param[out] bytes_read Optional. The number of bytes read
 * @return VMI_SUCCESS if read is complete, VMI_FAILURE otherwise
 */
status_t vmi_read_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    size_t count,
    void *buf,
    size_t *bytes_read
) NOEXCEPT;

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
    const char *sym,
    uint8_t * value) NOEXCEPT;

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
    const char *sym,
    uint16_t * value) NOEXCEPT;

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
    const char *sym,
    uint32_t * value) NOEXCEPT;

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
    const char *sym,
    uint64_t * value) NOEXCEPT;

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
    const char *sym,
    addr_t *value) NOEXCEPT;

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
    const char *sym) NOEXCEPT;

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
    vmi_pid_t pid,
    uint8_t * value) NOEXCEPT;

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
    vmi_pid_t pid,
    uint16_t * value) NOEXCEPT;

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
    vmi_pid_t pid,
    uint32_t * value) NOEXCEPT;

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
    vmi_pid_t pid,
    uint64_t * value) NOEXCEPT;

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
    vmi_pid_t pid,
    addr_t *value) NOEXCEPT;

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
    vmi_pid_t pid) NOEXCEPT;

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
    vmi_pid_t pid) NOEXCEPT;

/**
 * Converts character encoding from that in the input string to another
 * specified encoding. Two common ways to use this function are: (1) convert a
 * string to the "UTF-8" encoding and output with printf("%s") NOEXCEPT; (2) convert a
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
    const char *outencoding) NOEXCEPT;

/**
 * Convenience function to free a unicode_string_t struct.
 *
 * @param[in] p_us Pointer to a unicode_string_t struct
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_free_unicode_str(
    unicode_string_t *p_us) NOEXCEPT;

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
    uint8_t * value) NOEXCEPT;

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
    uint16_t * value) NOEXCEPT;

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
    uint32_t * value) NOEXCEPT;

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
    uint64_t * value) NOEXCEPT;

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
    addr_t *value) NOEXCEPT;

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
    addr_t paddr) NOEXCEPT;


/**
 * Writes count bytes to memory
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[in] count The number of bytes to write
 * @param[in] buf The data written to memory
 * @param[out] bytes_written Optional. The numer of bytes written
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t count,
    void *buf,
    size_t *bytes_written) NOEXCEPT;

/**
 * Writes count bytes to memory located at the kernel symbol sym
 * from a buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to write to
 * @param[in] count The number of bytes to write
 * @param[in] buf The data written to memory
 * @param[out] bytes_written Optional. The numer of bytes written
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_ksym(
    vmi_instance_t vmi,
    const char *sym,
    size_t count,
    void *buf,
    size_t *bytes_written) NOEXCEPT;

/**
 * Writes count bytes to memory located at the virtual address vaddr
 * from buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to write to
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] count The number of bytes to write
 * @param[in] buf The data written to memory
 * @param[out] bytes_written Optional. The numer of bytes written
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    size_t count,
    void *buf,
    size_t *bytes_written) NOEXCEPT;

/**
 * Writes count bytes to memory located at the physical address paddr
 * from buf.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to write to
 * @param[in] buf The data written to memory
 * @param[in] count The number of bytes to write
 * @param[out] bytes_written Optional. The numer of bytes written
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    size_t count,
    void *buf,
    size_t *bytes_written) NOEXCEPT;

/**
 * Writes 8 bits to memory
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_8(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint8_t * value) NOEXCEPT;

/**
 * Writes 16 bits to memory
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_16(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint16_t * value) NOEXCEPT;

/**
 * Writes 32 bits to memory
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_32(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint32_t * value) NOEXCEPT;

/**
 * Writes 64 bits to memory
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_64(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint64_t * value) NOEXCEPT;

/**
 * Writes the address to memory. The number of
 * bytes written is 8 for 64-bit systems and 4 for 32-bit systems.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] ctx Access context
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_addr(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t * value) NOEXCEPT;

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
    const char *sym,
    uint8_t * value) NOEXCEPT;

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
    const char *sym,
    uint16_t * value) NOEXCEPT;

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
    const char *sym,
    uint32_t * value) NOEXCEPT;

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
    const char *sym,
    uint64_t * value) NOEXCEPT;

/**
 * Writes the address to memory. The number of
 * bytes written is 8 for 64-bit systems and 4 for 32-bit systems.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] sym Kernel symbol to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_addr_ksym(
    vmi_instance_t vmi,
    const char *sym,
    addr_t * value) NOEXCEPT;

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
    vmi_pid_t pid,
    uint8_t * value) NOEXCEPT;

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
    vmi_pid_t pid,
    uint16_t * value) NOEXCEPT;

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
    vmi_pid_t pid,
    uint32_t * value) NOEXCEPT;

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
    vmi_pid_t pid,
    uint64_t * value) NOEXCEPT;

/**
 * Writes the address to memory. The number of
 * bytes written is 8 for 64-bit systems and 4 for 32-bit systems.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr Virtual address to write to
 * @param[in] pid Pid of the virtual address space (0 for kernel)
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_addr_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    addr_t * value) NOEXCEPT;

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
    uint8_t * value) NOEXCEPT;

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
    uint16_t * value) NOEXCEPT;

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
    uint32_t * value) NOEXCEPT;

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
    uint64_t * value) NOEXCEPT;

/**
 * Writes the address to memory. The number of
 * bytes written is 8 for 64-bit systems and 4 for 32-bit systems.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] paddr Physical address to write to
 * @param[in] value The value written to memory
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_write_addr_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    addr_t * value) NOEXCEPT;

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
    const unsigned char *data,
    unsigned long length) NOEXCEPT;

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
    const char *sym,
    size_t length) NOEXCEPT;

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
    vmi_pid_t pid,
    size_t length) NOEXCEPT;

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
    size_t length) NOEXCEPT;

/**
 * Gets the name of the VM (or file) that LibVMI is accessing.
 *
 * @param[in] vmi LibVMI instance
 * @return VM (or file) name, must be free'd by caller
 */
char *vmi_get_name(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Gets the id of the VM that LibVMI is accessing.
 *
 * @param[in] vmi LibVMI instance
 * @return VM id, or zero on error
 */
uint64_t vmi_get_vmid(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Gets the current access mode for LibVMI, which tells what
 * resource is being using to access the memory (e.g., VMI_XEN,
 * VMI_KVM, or VMI_FILE).
 *
 * If LibVMI is already initialized it will return the active
 * mode. If the LibVMI instance passed is NULL, it will
 * automatically determine the mode.
 *
 * @param[in] vmi LibVMI instance or NULL
 * @param[in] domain Unique name or id specifying the VM or file to view
 *                   Need to specify whether this is a domainname or domainid
 *                   by setting either VMI_INIT_DOMAINNAME or VMI_INIT_DOMAINID
 *                   on init_flags.
 * @param[in] init_flags Init flags to specify the domain input (name or id) and
 *                       to initialize further LibVMI features, such as events.
 * @param[in] init_data In case initialization requires additional information
 *                      for a given hypervisor, it can be provided via this
 *                      input.
 * @param[out] mode The access mode that was identified.
 * @return VMI_SUCCESS if LibVMI was able to access a hypervisor and found the
 *         given domain; VMI_FAILURE otherwise.
 */
status_t vmi_get_access_mode(
    vmi_instance_t vmi,
    const void *domain,
    uint64_t init_flags,
    vmi_init_data_t *init_data,
    vmi_mode_t *mode) NOEXCEPT;

/**
 * Gets the current page mode for LibVMI, which tells what
 * type of address translation is in use (e.g., VMI_PM_LEGACY,
 * VMI_PM_PAE, or VMI_PM_IA32E).
 *
 * On live VMs every call to this function will re-check the current state
 * of the specified vCPU. For file-mode it will just return the page-mode
 * that was determined using OS-specific heuristics.
 *
 *
 * @param[in] vmi LibVMI instance
 * @return Page mode
 */
page_mode_t vmi_get_page_mode(
    vmi_instance_t vmi,
    unsigned long vcpu) NOEXCEPT;

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
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Get the OS type that LibVMI is currently accessing.  This is
 * simple windows or linux (no version information).
 *
 * @param[in] vmi LibVMI instance
 * @return OS type
 */
os_t vmi_get_ostype(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Get the version info of Windows that LibVMI is currently accessing.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] info Pointer to structure to fill
 * @return True if success. False otherwise
 */
bool vmi_get_windows_build_info(
    vmi_instance_t vmi, win_build_info_t* info) NOEXCEPT;

/**
 * Get the version of Windows that LibVMI is currently accessing.  This is the
 * simple Windows version - no service pack or patch level is provided.
 *
 * @param[in] vmi LibVMI instance
 * @return Windows version
 */
win_ver_t vmi_get_winver(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Get the build number of Windows that LibVMI is currently accessing.
 *
 * @param[in] vmi LibVMI instance
 * @return Windows build number
 */
uint16_t vmi_get_win_buildnumber(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Get string represenatation of the version of Windows that LibVMI is currently accessing.
 *
 * @param[in] vmi LibVMI instance
 * @return string description of Windows version (do not free)
 */
const char *vmi_get_winver_str(
    vmi_instance_t vmi) NOEXCEPT;

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
    addr_t kdvb_pa) NOEXCEPT;

/**
 * Get the memory offset associated with the given offset_name.
 * Valid names include everything in the /etc/libvmi.conf file.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] offset_name String name for desired offset
 * @param[out] offset The offset value
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_get_offset(
    vmi_instance_t vmi,
    const char *offset_name,
    addr_t *offset) NOEXCEPT;

/**
 * Get the memory offset associated with the given symbol and subsymbol in the struct
 * @param[in] vmi LibVMI instance
 * @param[in] struct_name String name for desired symbol
 * @param[in] subsymbol String name for desired subsymbol
 * @param[out] offset of subsymbol in struct (symbol)
 *
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_get_kernel_struct_offset(
    vmi_instance_t vmi,
    const char* struct_name,
    const char* member,
    addr_t *addr) NOEXCEPT;

/**
 * Gets the current value for a VCPU xsave info.When LibVMI is accessing a raw
 * memory file or KVM, this function will fail.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vcpu The index of the VCPU to access, use 0 for single VCPU systems
 * @param[out] xsave_info Returned value of the xsave_info
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_get_xsave_info(
    vmi_instance_t vmi,
    unsigned long vcpu,
    xsave_area_t *xsave_info) NOEXCEPT;

/**
 * Gets the memory size of the guest or file that LibVMI is currently
 * accessing.  This is the amount of RAM allocated to the guest, but
 * does not necessarily indicate the highest addressable physical address;
 * get_max_physical_address() should be used.
 *
 * NOTE: if memory ballooning alters the allocation of memory to a
 *  VM after vmi_init, this information will have become stale
 *  and a re-initialization will be required.
 *
 * @param[in] vmi LibVMI instance
 * @return Memory size
 */
uint64_t vmi_get_memsize(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Gets highest addressable physical memory address of the guest or file that
 * LibVMI is currently accessing plus one.  That is, any address less then the
 * returned value "may be" a valid physical memory address, but the layout of
 * the guest RAM is hypervisor specific, so there can and will be holes that
 * are not memory pages and can't be read by libvmi.
 *
 * NOTE: if memory ballooning alters the allocation of memory to a VM after
 *  vmi_init, this information will have become stale and a re-initialization
 *  will be required.
 *
 * @param[in] vmi LibVMI instance @return physical memory size
 */
addr_t vmi_get_max_physical_address(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Gets the memory size of the guest that LibVMI is accessing.
 * This information is required for any interaction with of VCPU registers.
 *
 * @param[in] vmi LibVMI instance
 * @return Number of VCPUs
 */
unsigned int vmi_get_num_vcpus (
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Injects a page fault trap. It is assumed that the guest is in user-mode and in the proper
 * address space for the request to work.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vcpu The index of the VCPU to access, use 0 for single VCPU systems
 * @param[in] virtual_address The cr2 address for requested page fault
 * @param[in] error_code The error code for the requested page fault. ~0u means 'ignore'
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t
vmi_request_page_fault(
    vmi_instance_t vmi,
    unsigned long vcpu,
    uint64_t virtual_address,
    uint32_t error_code) NOEXCEPT;

/**
 * Gets the current value for tsc info.  This currently only
 * supports x86 registers.  When LibVMI is accessing a raw
 * memory file or KVM, this function will fail.
 *
 * @param[in] vmi LibVMI instance
 * @param[out] tsc_mode The tsc_mode value to be filled
 * @param[out] elapsed_nsec The elapsed time in nano sec to be filled
 * @param[out] gtsc_khz The guest tsc frequency in kHz
 * @param[out] incarnation The guest tsc incarnation (migration count)
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t
vmi_get_tsc_info(
    vmi_instance_t vmi,
    uint32_t *tsc_mode,
    uint64_t *elapsed_nsec,
    uint32_t *gtsc_khz,
    uint32_t *incarnation) NOEXCEPT;

/**
 * Gets the current value of VCPU mtrr registers.  This currently only
 * supports x86 registers.  When LibVMI is accessing a raw
 * memory file or KVM, this function will fail.
 *
 * @param[in] vmi LibVMI instance
 * @param[out] hwMtrr The mtrr struct to be filled
 * @param[in] vcpu The index of the VCPU to access, use 0 for single VCPU systems
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_get_vcpumtrr(
    vmi_instance_t vmi,
    mtrr_regs_t *hwMtrr,
    unsigned long vcpu) NOEXCEPT;

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
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu) NOEXCEPT;

/**
 * Gets the current value of VCPU registers.  This currently only
 * supports x86 registers.  When LibVMI is accessing a raw
 * memory file or KVM, this function will fail.
 *
 * @param[in] vmi LibVMI instance
 * @param[out] regs The register struct to be filled
 * @param[in] vcpu The index of the VCPU to access, use 0 for single VCPU systems
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu) NOEXCEPT;

/**
 * Sets the current value of a VCPU register.  This currently only
 * supports control registers.  When LibVMI is accessing a raw
 * memory file, this function will fail.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] value Value to assign to the register
 * @param[in] reg The register to access
 * @param[in] vcpu The index of the VCPU to access, use 0 for single VCPU systems
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu) NOEXCEPT;

/**
 * Sets the vCPU registers to the ones passed in the struct. It is important to have
 * a valid value in all registers when calling this function, so the user likely
 * wants to call vmi_get_vcpuregs before calling this function.
 * When LibVMI is accessing a raw memory file or KVM, this function will fail.
 *
 * @param[in] vmi LibVMI instance
 * @param[regs] regs The register struct holding the values to be set
 * @param[in] vcpu The index of the VCPU to access, use 0 for single VCPU systems
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu) NOEXCEPT;

/**
 * Pauses the VM.  Use vmi_resume_vm to resume the VM after pausing
 * it.  If accessing a memory file, this has no effect.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_pause_vm(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Resumes the VM.  Use vmi_pause_vm to pause the VM before calling
 * this function.  If accessing a memory file, this has no effect.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_resume_vm(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Removes all entries from LibVMI's internal virtual to physical address
 * cache.  This is generally only useful if you believe that an entry in
 * the cache is incorrect, or out of date.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] dtb The process address space to flush, or ~0ull for all.
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_v2pcache_flush(
    vmi_instance_t vmi,
    addr_t pt) NOEXCEPT;

/**
 * Removes all entries from LibVMI's internal virtual to physical address
 * cache.  This is generally only useful if you believe that an entry in
 * the cache is incorrect, or out of date.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] dtb The process address space to flush, or ~0ull for all.
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_v2pcache_nested_flush(
    vmi_instance_t vmi,
    addr_t pt,
    addr_t npt) NOEXCEPT;

/**
 * Adds one entry to LibVMI's internal virtual to physical address
 * cache.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] va Virtual address
 * @param[in] dtb Directory table base for va
 * @param[in] pa Physical address
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_v2pcache_add(
    vmi_instance_t vmi,
    addr_t va,
    addr_t pt,
    addr_t pa) NOEXCEPT;

/**
 * Adds one entry to LibVMI's internal virtual to physical address
 * cache.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] va Virtual address
 * @param[in] dtb Directory table base for va
 * @param[in] pa Physical address
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_v2pcache_nested_add(
    vmi_instance_t vmi,
    addr_t va,
    addr_t pt,
    addr_t npt,
    addr_t pa) NOEXCEPT;

/**
 * Removes all entries from LibVMI's internal kernel symbol to virtual address
 * cache.  This is generally only useful if you believe that an entry in
 * the cache is incorrect, or out of date.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_symcache_flush(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Adds one entry to LibVMI's internal symbol to virtual address
 * cache.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] base_addr Base address
 * @param[in] pid PID
 * @param[in] sym Symbol
 * @param[in] va Virtual address
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_symcache_add(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    char *sym,
    addr_t va) NOEXCEPT;

/**
 * Removes all entries from LibVMI's internal RVA to symbol
 * cache.  This is generally only useful if you believe that an entry in
 * the cache is incorrect, or out of date.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_rvacache_flush(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Adds one entry to LibVMI's internal RVA to symbol
 * cache.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] base_addr Base address
 * @param[in] pid PID
 * @param[in] rva Relative virtual address
 * @param[in] sym Symbol
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_rvacache_add(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    addr_t rva,
    char *sym) NOEXCEPT;

/**
 * Removes all entries from LibVMI's internal pid to directory table base
 * cache.  This is generally only useful if you believe that an entry in
 * the cache is incorrect, or out of date.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_pidcache_flush(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Adds one entry to LibVMI's internal pid to directory table base
 * cache.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] pid Process id
 * @param[in] dtb Directory table base
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_pidcache_add(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t dtb) NOEXCEPT;

/**
 * Removes all entries from LibVMI's internal page cache.  This is
 * generally only useful if you believe that an entry in the cache is
 * incorrect, or out of date.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
void vmi_pagecache_flush(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Returns the path of the Linux system map file for the given vmi instance
 *
 * DEPRECATED. Please use vmi_get_os_profile_path instead.
 *
 * @param[in] vmi LibVMI instance
 * @return String file path location of the Linux system map
 */
const char * vmi_get_linux_sysmap(vmi_instance_t vmi) NOEXCEPT;

/**
 * Returns the path of the FreeBSD system map file for the given vmi instance
 *
 * DEPRECATED. Please use vmi_get_os_profile_path instead.
 *
 * @param[in] vmi LibVMI instance
 * @return String file path location of the FreeBSD system map
 */
const char * vmi_get_freebsd_sysmap(vmi_instance_t vmi) NOEXCEPT;

/**
 * Get full path of associated rekall profile
 *
 * DEPRECATED. Please use vmi_get_os_profile_path instead.
 *
 * @param[in] vmi LibVMI instance
 * @return Full path of the rekall profile
 */
const char *vmi_get_rekall_path(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Get full path of associated OS profile.
 *
 * This can be either the Rekall profile, Volatility ISF or System.map file.
 *
 * @param[in] vmi LibVMI instance
 * @return Full path of the OS profile
 */
const char *vmi_get_os_profile_path(
    vmi_instance_t vmi) NOEXCEPT;

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif /* LIBVMI_H */

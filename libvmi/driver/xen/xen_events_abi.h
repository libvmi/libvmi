/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
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

#ifndef XEN_EVENTS_ABI_H
#define XEN_EVENTS_ABI_H

#include <config.h>
#include <xen/io/ring.h>

#ifndef HVM_PARAM_MONITOR_RING_PFN
#define HVM_PARAM_MONITOR_RING_PFN 28
#endif
#ifndef HVM_PARAM_ACCESS_RING_PFN
#define HVM_PARAM_ACCESS_RING_PFN 28
#endif

#define X86_TRAP_DEBUG  1
#define X86_TRAP_INT3   3
#define X86_TRAP_page_fault 14

#ifdef HAVE_XENMEM_ACCESS_T
#include <xen/memory.h>

typedef enum {
    HVMMEM_access_n,
    HVMMEM_access_r,
    HVMMEM_access_w,
    HVMMEM_access_rw,
    HVMMEM_access_x,
    HVMMEM_access_rx,
    HVMMEM_access_wx,
    HVMMEM_access_rwx,
    HVMMEM_access_rx2rw,
    HVMMEM_access_n2rwx,
    HVMMEM_access_default
} hvmmem_access_t;
#endif

#ifdef HAVE_HVMMEM_ACCESS_T
typedef enum {
    XENMEM_access_n,
    XENMEM_access_r,
    XENMEM_access_w,
    XENMEM_access_rw,
    XENMEM_access_x,
    XENMEM_access_rx,
    XENMEM_access_wx,
    XENMEM_access_rwx,
    XENMEM_access_rx2rw,
    XENMEM_access_n2rwx,
    XENMEM_access_default
} xenmem_access_t;
#endif

#define X86_TRAP_ext_int    0 /* external interrupt */
#define X86_TRAP_nmi        2 /* nmi */
#define X86_TRAP_hw_exc     3 /* hardware exception */
#define X86_TRAP_sw_int     4 /* software interrupt (CD nn) */
#define X86_TRAP_pri_sw_exc 5 /* ICEBP (F1) */
#define X86_TRAP_sw_exc     6 /* INT3 (CC), INTO (CE) */

#define HVMPME_mode_disabled   0
#define HVMPME_mode_async      1
#define HVMPME_mode_sync       2
#define HVMPME_onchangeonly    (1 << 2)

#define VM_EVENT_FLAG_VCPU_PAUSED        (1 << 0)
#define VM_EVENT_FLAG_FOREIGN            (1 << 1)
#define VM_EVENT_FLAG_EMULATE            (1 << 2)
#define VM_EVENT_FLAG_EMULATE_NOWRITE    (1 << 3)
#define VM_EVENT_FLAG_TOGGLE_SINGLESTEP  (1 << 4)
#define VM_EVENT_FLAG_SET_EMUL_READ_DATA (1 << 5)
#define VM_EVENT_FLAG_DENY               (1 << 6)
#define VM_EVENT_FLAG_ALTERNATE_P2M      (1 << 7)
#define VM_EVENT_FLAG_SET_REGISTERS      (1 << 8)
#define VM_EVENT_FLAG_SET_EMUL_INSN_DATA (1 << 9)
#define VM_EVENT_FLAG_GET_NEXT_INTERRUPT (1 << 10)
#define VM_EVENT_FLAG_FAST_SINGLESTEP    (1 << 11)
#define VM_EVENT_FLAG_NESTED_P2M         (1 << 12)
#define VM_EVENT_FLAG_RESET_VMTRACE      (1 << 13)

#define VM_EVENT_REASON_UNKNOWN                 0
#define VM_EVENT_REASON_MEM_ACCESS              1
#define VM_EVENT_REASON_MEM_SHARING             2
#define VM_EVENT_REASON_MEM_PAGING              3
#define VM_EVENT_REASON_WRITE_CTRLREG           4
#define VM_EVENT_REASON_MOV_TO_MSR              5
#define VM_EVENT_REASON_SOFTWARE_BREAKPOINT     6
#define VM_EVENT_REASON_SINGLESTEP              7
#define VM_EVENT_REASON_GUEST_REQUEST           8
#define VM_EVENT_REASON_DEBUG_EXCEPTION         9
#define VM_EVENT_REASON_CPUID                   10
#define VM_EVENT_REASON_PRIVILEGED_CALL         11
#define VM_EVENT_REASON_INTERRUPT               12
#define VM_EVENT_REASON_DESCRIPTOR_ACCESS       13
#define VM_EVENT_REASON_EMUL_UNIMPLEMENTED      14
#define XS_EVENT_REASON_DOMAIN_WATCH            15
#define __VM_EVENT_REASON_MAX                   16

#define VM_EVENT_X86_CR0    0
#define VM_EVENT_X86_CR3    1
#define VM_EVENT_X86_CR4    2
#define VM_EVENT_X86_XCR0   3

#define MEM_ACCESS_R                (1 << 0)
#define MEM_ACCESS_W                (1 << 1)
#define MEM_ACCESS_X                (1 << 2)
#define MEM_ACCESS_RWX              (MEM_ACCESS_R | MEM_ACCESS_W | MEM_ACCESS_X)
#define MEM_ACCESS_RW               (MEM_ACCESS_R | MEM_ACCESS_W)
#define MEM_ACCESS_RX               (MEM_ACCESS_R | MEM_ACCESS_X)
#define MEM_ACCESS_WX               (MEM_ACCESS_W | MEM_ACCESS_X)
#define MEM_ACCESS_GLA_VALID        (1 << 3)
#define MEM_ACCESS_FAULT_WITH_GLA   (1 << 4)
#define MEM_ACCESS_FAULT_IN_GPT     (1 << 5)

#define XEN_DOMCTL_MONITOR_EVENT_WRITE_CTRLREG         0
#define XEN_DOMCTL_MONITOR_EVENT_MOV_TO_MSR            1
#define XEN_DOMCTL_MONITOR_EVENT_SINGLESTEP            2
#define XEN_DOMCTL_MONITOR_EVENT_SOFTWARE_BREAKPOINT   3
#define XEN_DOMCTL_MONITOR_EVENT_GUEST_REQUEST         4
#define XEN_DOMCTL_MONITOR_EVENT_DEBUG_EXCEPTION       5
#define XEN_DOMCTL_MONITOR_EVENT_CPUID                 6
#define XEN_DOMCTL_MONITOR_EVENT_PRIVILEGED_CALL       7

struct regs_x86_1 {
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
    uint64_t fs_base;
    uint64_t gs_base;
    uint32_t cs_arbytes;
    uint32_t _pad;
};

struct x86_selector_reg {
    uint32_t limit  :    20;
    uint32_t ar     :    12;
};

struct regs_x86_4 {
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
    uint32_t cs_base;
    uint32_t ss_base;
    uint32_t ds_base;
    uint32_t es_base;
    uint64_t fs_base;
    uint64_t gs_base;
    struct x86_selector_reg cs;
    struct x86_selector_reg ss;
    struct x86_selector_reg ds;
    struct x86_selector_reg es;
    struct x86_selector_reg fs;
    struct x86_selector_reg gs;
    uint64_t shadow_gs;
    uint16_t cs_sel;
    uint16_t ss_sel;
    uint16_t ds_sel;
    uint16_t es_sel;
    uint16_t fs_sel;
    uint16_t gs_sel;
    uint32_t _pad;
};

struct regs_x86_5 {
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
    uint64_t gdtr_base;
    uint32_t cs_base;
    uint32_t ss_base;
    uint32_t ds_base;
    uint32_t es_base;
    uint64_t fs_base;
    uint64_t gs_base;
    struct x86_selector_reg cs;
    struct x86_selector_reg ss;
    struct x86_selector_reg ds;
    struct x86_selector_reg es;
    struct x86_selector_reg fs;
    struct x86_selector_reg gs;
    uint64_t shadow_gs;
    uint16_t gdtr_limit;
    uint16_t cs_sel;
    uint16_t ss_sel;
    uint16_t ds_sel;
    uint16_t es_sel;
    uint16_t fs_sel;
    uint16_t gs_sel;
    uint16_t _pad;
};

struct regs_x86_7 {
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
    uint64_t gdtr_base;
    uint64_t npt_base;
    uint64_t vmtrace_pos;
    uint32_t cs_base;
    uint32_t ss_base;
    uint32_t ds_base;
    uint32_t es_base;
    uint64_t fs_base;
    uint64_t gs_base;
    struct x86_selector_reg cs;
    struct x86_selector_reg ss;
    struct x86_selector_reg ds;
    struct x86_selector_reg es;
    struct x86_selector_reg fs;
    struct x86_selector_reg gs;
    uint64_t shadow_gs;
    uint16_t gdtr_limit;
    uint16_t cs_sel;
    uint16_t ss_sel;
    uint16_t ds_sel;
    uint16_t es_sel;
    uint16_t fs_sel;
    uint16_t gs_sel;
    uint16_t _pad;
};

struct regs_arm {
    uint64_t ttbr0;
    uint64_t ttbr1;
    uint64_t ttbcr;
    uint64_t pc;
    uint32_t cpsr;
    uint32_t _pad;
};

struct vm_event_mem_access {
    uint64_t gfn;
    uint64_t offset;
    uint64_t gla;
    uint32_t flags;
    uint32_t _pad;
};

struct vm_event_write_ctrlreg {
    uint32_t index;
    uint32_t _pad;
    uint64_t new_value;
    uint64_t old_value;
};

struct vm_event_singlestep {
    uint64_t gfn;
};

struct vm_event_fast_singlestep {
    uint16_t p2midx;
};

struct vm_event_debug_1 {
    uint64_t gfn;
};

struct vm_event_debug_2 {
    uint64_t gfn;
    uint32_t insn_length;
    uint8_t type;
    uint8_t _pad[3];
};

struct vm_event_debug_6 {
    uint64_t gfn;
    uint64_t pending_dbg;
    uint32_t insn_length;
    uint8_t type;
    uint8_t _pad[3];
};

struct vm_event_mov_to_msr_1 {
    uint64_t msr;
    uint64_t value;
};

struct vm_event_mov_to_msr_3 {
    uint64_t msr;
    uint64_t new_value;
    uint64_t old_value;
};

#define VM_EVENT_DESC_IDTR           1
#define VM_EVENT_DESC_GDTR           2
#define VM_EVENT_DESC_LDTR           3
#define VM_EVENT_DESC_TR             4

struct vm_event_desc_access_3 {
    union {
        struct {
            uint32_t instr_info;         /* VMX: VMCS Instruction-Information */
            uint32_t _pad1;
            uint64_t exit_qualification; /* VMX: VMCS Exit Qualification */
        } vmx;
        struct {
            uint64_t exitinfo;           /* SVM: VMCB EXITINFO */
            uint64_t _pad2;
        } svm;
    } arch;
    uint8_t descriptor;                  /* VM_EVENT_DESC_* */
    uint8_t is_write;
    uint8_t _pad[6];
};

struct vm_event_desc_access_6 {
    union {
        struct {
            uint32_t instr_info;         /* VMX: VMCS Instruction-Information */
            uint32_t _pad1;
            uint64_t exit_qualification; /* VMX: VMCS Exit Qualification */
        } vmx;
    } arch;
    uint8_t descriptor;                  /* VM_EVENT_DESC_* */
    uint8_t is_write;
    uint8_t _pad[6];
};

struct vm_event_cpuid {
    uint32_t insn_length;
    uint32_t leaf;
    uint32_t subleaf;
    uint32_t _pad;
};

struct vm_event_emul_read_data_1 {
    uint32_t size;
    uint8_t  data[sizeof(struct regs_x86_1) - sizeof(uint32_t)];
};

struct vm_event_emul_read_data_4 {
    uint32_t size;
    uint8_t  data[sizeof(struct regs_x86_4) - sizeof(uint32_t)];
};

struct vm_event_emul_read_data_5 {
    uint32_t size;
    uint8_t  data[sizeof(struct regs_x86_5) - sizeof(uint32_t)];
};

struct vm_event_emul_insn_data {
    uint8_t data[16];
};

struct vm_event_interrupt_x86 {
    uint32_t vector;
    uint32_t type;
    uint32_t error_code;
    uint32_t _pad;
    uint64_t cr2;
};

typedef struct vm_event_st_1 {
    uint32_t version;
    uint32_t flags;
    uint32_t reason;
    uint32_t vcpu_id;
    uint16_t altp2m_idx;
    uint16_t _pad[3];

    union {
        struct vm_event_mem_access            mem_access;
        struct vm_event_write_ctrlreg         write_ctrlreg;
        struct vm_event_mov_to_msr_1          mov_to_msr;
        struct vm_event_debug_1               singlestep;
        struct vm_event_debug_1               software_breakpoint;
    } u;

    union {
        union {
            struct regs_x86_1 x86;
        } regs;

        struct vm_event_emul_read_data_1 emul_read_data;
    } data;
} vm_event_1_request_t, vm_event_1_response_t;

typedef struct vm_event_st_2 {
    uint32_t version;
    uint32_t flags;
    uint32_t reason;
    uint32_t vcpu_id;
    uint16_t altp2m_idx;
    uint16_t _pad[3];

    union {
        struct vm_event_mem_access            mem_access;
        struct vm_event_write_ctrlreg         write_ctrlreg;
        struct vm_event_mov_to_msr_1          mov_to_msr_1;
        struct vm_event_singlestep            singlestep;
        struct vm_event_debug_2               software_breakpoint;
        struct vm_event_debug_2               debug_exception;
        struct vm_event_cpuid                 cpuid;
        union {
            struct vm_event_interrupt_x86     x86;
        } interrupt;
    } u;

    union {
        union {
            struct regs_x86_1 x86;
            struct regs_arm arm;
        } regs;

        union {
            struct vm_event_emul_read_data_1 read;
            struct vm_event_emul_insn_data insn;
        } emul;
    } data;
} vm_event_2_request_t, vm_event_2_response_t;

typedef struct vm_event_st_3 {
    uint32_t version;
    uint32_t flags;
    uint32_t reason;
    uint32_t vcpu_id;
    uint16_t altp2m_idx;
    uint16_t _pad[3];

    union {
        struct vm_event_mem_access            mem_access;
        struct vm_event_write_ctrlreg         write_ctrlreg;
        struct vm_event_mov_to_msr_3          mov_to_msr_3;
        struct vm_event_desc_access_3         desc_access;
        struct vm_event_singlestep            singlestep;
        struct vm_event_debug_2               software_breakpoint;
        struct vm_event_debug_2               debug_exception;
        struct vm_event_cpuid                 cpuid;
        union {
            struct vm_event_interrupt_x86     x86;
        } interrupt;
    } u;

    union {
        union {
            struct regs_x86_1 x86;
            struct regs_arm arm;
        } regs;

        union {
            struct vm_event_emul_read_data_1 read;
            struct vm_event_emul_insn_data insn;
        } emul;
    } data;
} vm_event_3_request_t, vm_event_3_response_t;

typedef struct vm_event_st_4 {
    uint32_t version;
    uint32_t flags;
    uint32_t reason;
    uint32_t vcpu_id;
    uint16_t altp2m_idx;
    uint16_t _pad[3];

    union {
        struct vm_event_mem_access            mem_access;
        struct vm_event_write_ctrlreg         write_ctrlreg;
        struct vm_event_mov_to_msr_3          mov_to_msr;
        struct vm_event_desc_access_3         desc_access;
        struct vm_event_singlestep            singlestep;
        struct vm_event_debug_2               software_breakpoint;
        struct vm_event_debug_2               debug_exception;
        struct vm_event_cpuid                 cpuid;
        union {
            struct vm_event_interrupt_x86     x86;
        } interrupt;
    } u;

    union {
        union {
            struct regs_x86_4 x86;
            struct regs_arm arm;
        } regs;

        union {
            struct vm_event_emul_read_data_4 read;
            struct vm_event_emul_insn_data insn;
        } emul;
    } data;
} vm_event_4_request_t, vm_event_4_response_t;

typedef struct vm_event_st_5 {
    uint32_t version;
    uint32_t flags;
    uint32_t reason;
    uint32_t vcpu_id;
    uint16_t altp2m_idx;
    uint16_t _pad[3];

    union {
        struct vm_event_mem_access            mem_access;
        struct vm_event_write_ctrlreg         write_ctrlreg;
        struct vm_event_mov_to_msr_3          mov_to_msr;
        struct vm_event_desc_access_3         desc_access;
        struct vm_event_singlestep            singlestep;
        struct vm_event_debug_2               software_breakpoint;
        struct vm_event_debug_2               debug_exception;
        struct vm_event_cpuid                 cpuid;
        union {
            struct vm_event_interrupt_x86     x86;
        } interrupt;
    } u;

    union {
        union {
            struct regs_x86_5 x86;
            struct regs_arm arm;
        } regs;

        union {
            struct vm_event_emul_read_data_5 read;
            struct vm_event_emul_insn_data insn;
        } emul;
    } data;
} vm_event_5_request_t, vm_event_5_response_t;

typedef struct vm_event_st_6 {
    uint32_t version;
    uint32_t flags;
    uint32_t reason;
    uint32_t vcpu_id;
    uint16_t altp2m_idx;
    uint16_t _pad[3];

    union {
        struct vm_event_mem_access            mem_access;
        struct vm_event_write_ctrlreg         write_ctrlreg;
        struct vm_event_mov_to_msr_3          mov_to_msr;
        struct vm_event_desc_access_6         desc_access;
        struct vm_event_singlestep            singlestep;
        struct vm_event_fast_singlestep       fast_singlestep;
        struct vm_event_debug_6               software_breakpoint;
        struct vm_event_debug_6               debug_exception;
        struct vm_event_cpuid                 cpuid;
        union {
            struct vm_event_interrupt_x86     x86;
        } interrupt;
    } u;

    union {
        union {
            struct regs_x86_5 x86;
            struct regs_arm arm;
        } regs;

        union {
            struct vm_event_emul_read_data_5 read;
            struct vm_event_emul_insn_data insn;
        } emul;
    } data;
} vm_event_6_request_t, vm_event_6_response_t;

typedef struct vm_event_st_7 {
    uint32_t version;
    uint32_t flags;
    uint32_t reason;
    uint32_t vcpu_id;
    uint16_t altp2m_idx;
    uint16_t _pad[3];

    union {
        struct vm_event_mem_access            mem_access;
        struct vm_event_write_ctrlreg         write_ctrlreg;
        struct vm_event_mov_to_msr_3          mov_to_msr;
        struct vm_event_desc_access_6         desc_access;
        struct vm_event_singlestep            singlestep;
        struct vm_event_fast_singlestep       fast_singlestep;
        struct vm_event_debug_6               software_breakpoint;
        struct vm_event_debug_6               debug_exception;
        struct vm_event_cpuid                 cpuid;
        union {
            struct vm_event_interrupt_x86     x86;
        } interrupt;
    } u;

    union {
        union {
            struct regs_x86_7 x86;
            struct regs_arm arm;
        } regs;

        union {
            struct vm_event_emul_read_data_5 read;
            struct vm_event_emul_insn_data insn;
        } emul;
    } data;
} vm_event_7_request_t, vm_event_7_response_t;

DEFINE_RING_TYPES(vm_event_1, vm_event_1_request_t, vm_event_1_response_t);
DEFINE_RING_TYPES(vm_event_2, vm_event_2_request_t, vm_event_2_response_t);
DEFINE_RING_TYPES(vm_event_3, vm_event_3_request_t, vm_event_3_response_t);
DEFINE_RING_TYPES(vm_event_4, vm_event_4_request_t, vm_event_4_response_t);
DEFINE_RING_TYPES(vm_event_5, vm_event_5_request_t, vm_event_5_response_t);
DEFINE_RING_TYPES(vm_event_6, vm_event_6_request_t, vm_event_6_response_t);
DEFINE_RING_TYPES(vm_event_7, vm_event_7_request_t, vm_event_7_response_t);

#endif

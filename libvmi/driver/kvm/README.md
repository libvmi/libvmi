# KVM Driver

## Overview

The actual KVM driver contains 2 implementations

- KVMi: the new [KVM virtual machine introspection API](https://static.sched.com/hosted_files/kvmforum2019/f6/Advanced%20VMI%20on%20KVM%3A%20A%20progress%20Report.pdf)
- Legacy: the legacy KVM driver for LibVMI, using either `GDB` or the `fast-memaccess` patches available in `libvmi/tools/qemu-kvm-patch`

## LibVMI API Implementation

This section will give an implementation status of the LibVMI API on the new KVM driver.

- [x] r/w physical memory
- [ ] VCPU registers (x86 only)
    - [ ] read
        - [x] general purpose registers
        - [x] control registers
        - [ ] debug registers
        - [x] segment registers
        - [ ] MSR
            - only essential MSRs are retrieved
        - [x] IDTR/GDTR
    - [ ] write
        - [x] general purpose registers
        - [ ] control registers
        - [ ] debug registers
        - [ ] segment registers
        - [ ] MSR
        - [ ] IDTR/GDTR
- [x] memory size
- [x] pause / resume
- [x] request page fault
- [ ] guest memory mapping
- [ ] TSC info
  - [ ] `tsc_mode`
  - [ ] `elapsed_nsec`
  - [x] `gtsc_khz`
  - [ ] `incarnation`
- [ ] MTRR
- [ ] XSAVE
- [ ] SLAT
- [ ] VMI Events
    - [ ] singlestep (not supported in `KVMi-v6`)
    - [ ] register access
        - [ ] `reg_event.reg`
            - [x] CR
            - [ ] MSR
                - [ ] `MSR_ALL` (loop over all defined MSRs in LibVMI. Unable to set intercept on any kind of MSR in `KVMi-v6`)
        - [ ] `reg_event.equal`
        - [ ] `reg_event.async`
        - [ ] `reg_event.onchange`
        - [ ] `reg_event.in_access`
            - [x] `VMI_REGACCESS_N`
            - [x] `VMI_REGACCESS_W`
            - [ ] `VMI_REGACCESS_R` (not available in `KVMi-v6`)
            - [ ] `VMI_REGACCESS_RW` (not available in `KVMi-v6`)
        - [ ] `reg_event.out_access`
        - [x] `reg_event.value`
        - [x] `reg_event.previous`
        - [x] `reg_event.msr`
    - [ ] interrupt
        - [ ] `interrupt_event.intr`
            - [x] `INT3`
            - [ ] `INT_NEXT`
        - [ ] `interrupt_event.insn_length`
        - [x] `interrupt_event.reinject`
        - [ ] `interrupt_event.vector`
        - [ ] `interrupt_event.type`
        - [ ] `interrupt_event.error_code`
        - [x] `interrupt_event.cr2`
        - [x] `interrupt_event.gla`
        - [x] `interrupt_event.gfn`
        - [x] `interrupt_event.offset`
    - [ ] memory access
        - [x] `mem_event.gfn`
        - [x] `mem_event.generic`
        - [x] `mem_event.in_access`
        - [x] `mem_event.out_access`
        - [ ] `mem_event.gptw`
        - [ ] `mem_event.gla_valid`
        - [x] `mem_event.gla`
        - [x] `mem_event.offset`
    - [ ] cpuid
    - [ ] privcall
    - [ ] descriptor
        - [ ] `desc_event.instr_info`
        - [ ] `desc_event.exit_qualification`
        - [ ] `desc_event.exit_info`
        - [x] `desc_event.descriptor`
        - [x] `desc_event.is_write`
- [ ] VMI Event response
    - [x] `VMI_EVENT_RESPONSE_NONE`
    - [ ] `VMI_EVENT_RESPONSE_EMULATE`
    - [ ] `VMI_EVENT_RESPONSE_EMULATE_NOWRITE`
    - [x] `VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA` (only for memory access events)
    - [ ] `VMI_EVENT_RESPONSE_DENY`
    - [x] `VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP`
    - [ ] `VMI_EVENT_RESPONSE_SLAT_ID`
    - [ ] `VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID`
    - [x] `VMI_EVENT_RESPONSE_SET_REGISTERS`
    - [ ] `VMI_EVENT_RESPONSE_SET_EMUL_INSN`
    - [ ] `VMI_EVENT_RESPONSE_GET_NEXT_INTERRUPT`

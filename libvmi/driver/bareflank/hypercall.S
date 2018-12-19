# The LibVMI Library is an introspection library that simplifies access to
# memory in a target virtual machine or in a file containing a dump of
# a system's physical memory.  LibVMI is based on the XenAccess Library.
#
# Author: Tamas K Lengyel (lengyelt@ainfosec.com)
#
# This file is part of LibVMI.
#
# LibVMI is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# LibVMI is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.

# The bareflank hypercall interface
# This currently assumes System V ABI:
# ret: %rax; p1: %rdi; p2: %rsi; p3: %rdx; p4: %r8; p5: %r9

#include "hypercall.h"
.section .text

.globl bareflank_cpuid
.type bareflank_cpuid, @function
bareflank_cpuid:
    push %rbx                 # rbx is to be preserved according to System V
    movq     %rdx,%r8         # Save rdx (p3) before it gets clobbered
    movq     $1073746743,%rax # Move magic value (0x40001337) into rax
    cpuid
    movq     %rbx,(%rdi)
    movq     %rcx,(%rsi)
    movq     %rdx,(%r8)
    pop %rbx
    ret

.globl hcall_get_registers
.type hcall_get_registers, @function
hcall_get_registers:
    mov $HCALL_GET_REGISTERS,%rax       # Move hcall id into rax
    vmcall
    ret

.globl hcall_v2p
.type hcall_v2p, @function
hcall_v2p:
    mov $HCALL_TRANSLATE_V2P,%rax       # Move hcall id into rax
    vmcall
    movq     %rdi,(%rsi)
    ret

.globl hcall_map_pa
.type hcall_map_pa, @function
hcall_map_pa:
    mov $HCALL_MAP_PA,%rax       # Move hcall id into rax
    vmcall
    ret

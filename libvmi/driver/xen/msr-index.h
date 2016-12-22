/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
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
#ifndef MSR_INDEX_H
#define MSR_INDEX_H

#define _MSR_EFER                0xc0000080 /* extended feature register */
#define _MSR_STAR                0xc0000081 /* legacy mode SYSCALL target */
#define _MSR_LSTAR               0xc0000082 /* long mode SYSCALL target */
#define _MSR_CSTAR               0xc0000083 /* compat mode SYSCALL target */
#define _MSR_SYSCALL_MASK        0xc0000084 /* EFLAGS mask for syscall */
#define _MSR_TSC_AUX             0xc0000103 /* Auxiliary TSC */

#endif /* MSR_INDEX_H */

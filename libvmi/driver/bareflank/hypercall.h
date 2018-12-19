/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * Author: Tamas K Lengyel <lengyelt@ainfosec.com>
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

#ifndef BAREFLANK_HYPERCALL_H
#define BAREFLANK_HYPERCALL_H

#define HSTATUS_SUCCESS 0
#define HSTATUS_FAILURE !HSTATUS_SUCCESS

#define HCALL_INVALID       0
#define HCALL_ACK           1
#define HCALL_GET_REGISTERS 2
#define HCALL_SET_REGISTERS 3
#define HCALL_TRANSLATE_V2P 4
#define HCALL_MAP_PA        5

#endif

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

#ifndef LIBVMI_VOLATILITY_IST_H
#define LIBVMI_VOLATILITY_IST_H

#include "private.h"

#ifdef VOLATILITY_IST

status_t
volatility_ist_symbol_to_rva(
    json_object *json,
    const char *symbol,
    const char *subsymbol,
    addr_t *rva,
    size_t *size);

const char* volatility_get_os_type(vmi_instance_t vmi);

status_t
volatility_profile_bitfield_offset_and_size(
    json_object *json,
    const char *symbol,
    const char *subsymbol,
    addr_t *rva,
    size_t *start_bit,
    size_t *end_bit);

status_t
volatility_struct_field_type_name(
    json_object *json,
    const char *struct_name,
    const char *struct_member,
    const char **member_type_name);

#else

static inline status_t volatility_ist_symbol_to_rva(
    json_object *json,
    const char *symbol,
    const char *subsymbol,
    addr_t *rva,
    size_t *size)
{
    return VMI_FAILURE;
}
static inline const char* volatility_get_os_type(vmi_instance_t vmi)
{
    return NULL;
}

static inline status_t
volatility_profile_bitfield_offset_and_size(
    __attribute__((__unused__)) json_object *json,
    __attribute__((__unused__)) const char *symbol,
    __attribute__((__unused__)) const char *subsymbol,
    __attribute__((__unused__)) addr_t *rva,
    __attribute__((__unused__)) size_t *start_bit,
    __attribute__((__unused__)) size_t *end_bit)
{
    return VMI_FAILURE;
}

static inline status_t
volatility_struct_field_type_name(
    __attribute__((__unused__)) json_object *json,
    __attribute__((__unused__)) const char *struct_name,
    __attribute__((__unused__)) const char *struct_member,
    __attribute__((__unused__)) const char **member_type_name)
{
    return VMI_FAILURE;
}

#endif

#endif /* LIBVMI_VOLATILITY_IST_H */

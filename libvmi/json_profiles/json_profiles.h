/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel <tamas@tklengyel.com>
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

#ifndef LIBVMI_JSON_PROFILES_H
#define LIBVMI_JSON_PROFILES_H

#ifdef ENABLE_JSON_PROFILES
#define LIBVMI_EXTRA_JSON

#include <json-c/json.h>
#include "private.h"
#include "json_profiles/rekall.h"
#include "json_profiles/volatility_ist.h"

typedef struct json_interface {
    const char *path; /**< JSON profile's path for domain's running kernel */

    json_object *root;

    status_t (*handler)(
        json_object *json,
        const char *symbol,
        const char *subsymbol,
        addr_t *rva,
        size_t *size);

    status_t
    (*bitfield_offset_and_size)(
        json_object *json,
        const char *symbol,
        const char *subsymbol,
        addr_t *rva,
        size_t *start_bit,
        size_t *end_bit);

    status_t
    (*struct_field_type_name)(
        json_object *json,
        const char *struct_name,
        const char *struct_member,
        const char **member_type_name);

    const char* (*get_os_type)(
        vmi_instance_t vmi);
} json_interface_t;

bool json_profile_init(vmi_instance_t vmi, const char* path);

void json_profile_destroy(vmi_instance_t vmi);

#endif
#endif /* LIBVMI_JSON_PROFILES_H */

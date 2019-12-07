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

#include <stdbool.h>

#include "private.h"
#include "json_profiles.h"

typedef enum json_profile_type {
    JPT_INVALID,
    JPT_REKALL_PROFILE,
    JPT_VOLATILITY_IST
} json_profile_type_t;

bool json_profile_init(vmi_instance_t vmi, const char* path)
{
    json_interface_t *json = &vmi->json;

    if ( json->path ) {
        errprint("Duplicate JSON profile detected: %s\n", path);
        return false;
    }

    json->path = g_strdup(path);
    json->root = json_object_from_file(json->path);

    if (!json->root) {
        errprint("JSON at %s couldn't be opened!\n", path);
        g_free((char*)json->path);
        json->path = NULL;
        return false;
    }

    json_object *metadata = NULL;
    json_profile_type_t type = JPT_INVALID;

    if (json_object_object_get_ex(vmi->json.root, "metadata", &metadata))
        type = JPT_VOLATILITY_IST;
    else if (json_object_object_get_ex(vmi->json.root, "$METADATA", &metadata))
        type = JPT_REKALL_PROFILE;

    switch ( type ) {
        case JPT_VOLATILITY_IST:
            json->handler = volatility_ist_symbol_to_rva;
            json->get_os_type = volatility_get_os_type;
            break;
        case JPT_REKALL_PROFILE:
            json->handler = rekall_profile_symbol_to_rva;
            json->get_os_type = rekall_get_os_type;
            break;
        default:
            return false;
    };

    return true;
}

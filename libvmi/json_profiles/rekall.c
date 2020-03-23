/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel (tamas@tklengyel.com)
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

#include "private.h"
#include <stdio.h>
#include <json-c/json.h>

status_t
rekall_profile_symbol_to_rva(
    json_object *json,
    const char *symbol,
    const char *subsymbol,
    addr_t *rva,
    size_t *size)
{
    status_t ret = VMI_FAILURE;
    if (!json || !symbol) {
        return ret;
    }

    if (!subsymbol && !size) {
        json_object *constants = NULL, *functions = NULL, *jsymbol = NULL;
        if (json_object_object_get_ex(json, "$CONSTANTS", &constants)) {
            if (json_object_object_get_ex(constants, symbol, &jsymbol)) {
                *rva = json_object_get_int64(jsymbol);

                ret = VMI_SUCCESS;
                goto exit;
            } else {
                dbprint(VMI_DEBUG_MISC, "Rekall profile: symbol '%s' not found in $CONSTANTS\n", symbol);
            }
        } else {
            dbprint(VMI_DEBUG_MISC, "Rekall profile: no $CONSTANTS section found\n");
        }

        if (json_object_object_get_ex(json, "$FUNCTIONS", &functions)) {
            if (json_object_object_get_ex(functions, symbol, &jsymbol)) {
                *rva = json_object_get_int64(jsymbol);

                ret = VMI_SUCCESS;
                goto exit;
            } else {
                dbprint(VMI_DEBUG_MISC, "Rekall profile: symbol '%s' not found in $FUNCTIONS\n", symbol);
            }
        } else {
            dbprint(VMI_DEBUG_MISC, "Rekall profile: no $FUNCTIONS section found\n");
        }
    } else {
        json_object *structs = NULL, *jstruct = NULL, *jstruct2 = NULL, *jmember = NULL, *jvalue = NULL;
        if (!json_object_object_get_ex(json, "$STRUCTS", &structs)) {
            dbprint(VMI_DEBUG_MISC, "Rekall profile: no $STRUCTS section found\n");
            goto exit;
        }
        if (!json_object_object_get_ex(structs, symbol, &jstruct)) {
            dbprint(VMI_DEBUG_MISC, "Rekall profile: no %s found\n", symbol);
            goto exit;
        }

        if (size) {
            json_object* jsize = json_object_array_get_idx(jstruct, 0);
            *size = json_object_get_int64(jsize);

            ret = VMI_SUCCESS;
            goto exit;
        }

        jstruct2 = json_object_array_get_idx(jstruct, 1);
        if (!jstruct2) {
            dbprint(VMI_DEBUG_MISC, "Rekall profile: struct %s has no second element\n", symbol);
            goto exit;
        }

        if (!json_object_object_get_ex(jstruct2, subsymbol, &jmember)) {
            dbprint(VMI_DEBUG_MISC, "Rekall profile: %s has no %s member\n", symbol, subsymbol);
            goto exit;
        }

        jvalue = json_object_array_get_idx(jmember, 0);
        if (!jvalue) {
            dbprint(VMI_DEBUG_MISC, "Rekall profile: %s.%s has no RVA defined\n", symbol, subsymbol);
            goto exit;
        }

        *rva = json_object_get_int64(jvalue);
        ret = VMI_SUCCESS;
    }

exit:
    dbprint(VMI_DEBUG_MISC, "Rekall profile lookup %s %s: 0x%lx\n", symbol ?: NULL, subsymbol ?: NULL, *rva);

    return ret;
}

status_t
rekall_profile_bitfield_offset_and_size(
    json_object *json,
    const char *symbol,
    const char *subsymbol,
    addr_t *rva,
    size_t *start_bit,
    size_t *end_bit)
{
    status_t ret = VMI_FAILURE;
    if (!json || !symbol) {
        return ret;
    }

    json_object *structs = NULL, *jstruct = NULL, *jstruct2 = NULL, *jstruct3 = NULL, *jmember = NULL, *jvalue = NULL;
    if (!json_object_object_get_ex(json, "$STRUCTS", &structs)) {
        dbprint(VMI_DEBUG_MISC, "Rekall profile: no $STRUCTS section found\n");
        goto exit;
    }
    if (!json_object_object_get_ex(structs, symbol, &jstruct)) {
        dbprint(VMI_DEBUG_MISC, "Rekall profile: no %s found\n", symbol);
        goto exit;
    }

    jstruct2 = json_object_array_get_idx(jstruct, 1);
    if (!jstruct2) {
        dbprint(VMI_DEBUG_MISC, "Rekall profile: struct %s has no second element\n", symbol);
        goto exit;
    }

    if (!json_object_object_get_ex(jstruct2, subsymbol, &jmember)) {
        dbprint(VMI_DEBUG_MISC, "Rekall profile: %s has no %s member\n", symbol, subsymbol);
        goto exit;
    }

    jvalue = json_object_array_get_idx(jmember, 0);
    if (!jvalue) {
        dbprint(VMI_DEBUG_MISC, "Rekall profile: %s.%s has no RVA defined\n", symbol, subsymbol);
        goto exit;
    }

    *rva = json_object_get_int64(jvalue);

    jvalue = json_object_array_get_idx(jmember, 1);
    if (!jvalue) {
        dbprint(VMI_DEBUG_MISC, "Rekall profile: %s.%s has no BitField declaration\n", symbol, subsymbol);
        goto exit;
    }

    jstruct3 = json_object_array_get_idx(jvalue, 1);
    if (!jvalue) {
        dbprint(VMI_DEBUG_MISC, "Rekall profile: %s.%s has no BitField definition\n", symbol, subsymbol);
        goto exit;
    }

    if (!json_object_object_get_ex(jstruct3, "start_bit", &jvalue)) {
        dbprint(VMI_DEBUG_MISC, "Rekall profile: %s.%s has no member start_bit\n", symbol, subsymbol);
        goto exit;
    }
    *start_bit = json_object_get_int64(jvalue);

    if (!json_object_object_get_ex(jstruct3, "end_bit", &jvalue)) {
        dbprint(VMI_DEBUG_MISC, "Rekall profile: %s.%s has no member end_bit\n", symbol, subsymbol);
        goto exit;
    }
    *end_bit = json_object_get_int64(jvalue);

    ret = VMI_SUCCESS;

exit:
    dbprint(VMI_DEBUG_MISC, "Rekall profile lookup %s %s: offset 0x%lx, start bit %ld, end bit %ld\n", symbol ?: NULL, subsymbol ?: NULL, *rva, *start_bit, *end_bit);

    return ret;
}

const char* rekall_get_os_type(vmi_instance_t vmi)
{
    json_object *metadata = NULL, *os = NULL;

    if ( !json_object_object_get_ex(vmi->json.root, "$METADATA", &metadata) )
        return NULL;
    if ( !json_object_object_get_ex(metadata, "ProfileClass", &os) )
        return NULL;

    if ( !strcmp("Linux", json_object_get_string(os)) )
        return "Linux";
    else
        return "Windows";

    return NULL;
}

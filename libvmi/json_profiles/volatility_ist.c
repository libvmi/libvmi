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
volatility_ist_symbol_to_rva(
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
        json_object *symbols = NULL, *jsymbol = NULL, *address = NULL;
        if (!json_object_object_get_ex(json, "symbols", &symbols)) {
            dbprint(VMI_DEBUG_MISC, "Volatility IST profile: no symbols section found\n");
            goto exit;
        }
        if (!json_object_object_get_ex(symbols, symbol, &jsymbol)) {
            dbprint(VMI_DEBUG_MISC, "Volatility IST: symbol '%s' not found in symbols\n", symbol);
            goto exit;
        }
        if (!json_object_object_get_ex(jsymbol, "address", &address)) {
            dbprint(VMI_DEBUG_MISC, "Volatility IST: no address found for %s\n", symbol);
            goto exit;
        }

        *rva = json_object_get_int64(address);
        ret = VMI_SUCCESS;
    } else {
        json_object *user_types = NULL, *jstruct = NULL, *jstruct2 = NULL, *jmember = NULL, *jvalue = NULL;
        if (!json_object_object_get_ex(json, "user_types", &user_types)) {
            dbprint(VMI_DEBUG_MISC, "Volatility IST profile: no user_types section found\n");
            goto exit;
        }
        if (!json_object_object_get_ex(user_types, symbol, &jstruct)) {
            dbprint(VMI_DEBUG_MISC, "Volatility IST profile: no %s found\n", symbol);
            goto exit;
        }

        if (size) {
            json_object* jsize = NULL;

            if (!json_object_object_get_ex(jstruct, "size", &jsize)) {
                dbprint(VMI_DEBUG_MISC, "Volatility IST profile: Struct '%s' size not found\n", symbol);
                goto exit;
            }

            *size = json_object_get_int64(jsize);

            ret = VMI_SUCCESS;
            goto exit;
        }

        if (!json_object_object_get_ex(jstruct, "fields", &jstruct2)) {
            dbprint(VMI_DEBUG_MISC, "Volatility IST profile: struct %s has no fields element\n", symbol);
            goto exit;
        }

        if (!json_object_object_get_ex(jstruct2, subsymbol, &jmember)) {
            dbprint(VMI_DEBUG_MISC, "Volatility IST profile: %s has no %s member\n", symbol, subsymbol);
            goto exit;
        }

        if (!json_object_object_get_ex(jmember, "offset", &jvalue)) {
            dbprint(VMI_DEBUG_MISC, "Volatility IST profile: %s.%s has no offset defined\n", symbol, subsymbol);
            goto exit;
        }

        *rva = json_object_get_int64(jvalue);
        ret = VMI_SUCCESS;
    }

exit:
    dbprint(VMI_DEBUG_MISC, "Volatility IST profile lookup %s %s: 0x%lx\n", symbol ?: NULL, subsymbol ?: NULL, *rva);
    return ret;
}

const char *volatility_get_os_type(vmi_instance_t vmi)
{
    json_object *metadata = NULL, *os = NULL;

    if (!json_object_object_get_ex(vmi->json.root, "metadata", &metadata)) {
        dbprint(VMI_DEBUG_MISC, "Volatility IST profile: no metadata section found\n");
        return NULL;
    }

    if (json_object_object_get_ex(metadata, "windows", &os))
        return "Windows";

    return "Linux";
}

status_t
volatility_profile_bitfield_offset_and_size(
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

    json_object *user_types = NULL, *jstruct = NULL, *fields = NULL, *type = NULL, *jmember = NULL, *jvalue = NULL;
    if (!json_object_object_get_ex(json, "user_types", &user_types)) {
        dbprint(VMI_DEBUG_MISC, "Volatility profile: no user_types section found\n");
        goto exit;
    }
    if (!json_object_object_get_ex(user_types, symbol, &jstruct)) {
        dbprint(VMI_DEBUG_MISC, "Volatility profile: no %s found\n", symbol);
        goto exit;
    }
    if (!json_object_object_get_ex(jstruct, "fields", &fields)) {
        dbprint(VMI_DEBUG_MISC, "Volatility profile: no fields found\n");
        goto exit;
    }
    if (!json_object_object_get_ex(fields, subsymbol, &jmember)) {
        dbprint(VMI_DEBUG_MISC, "Volatility profile: %s has no %s member\n", symbol, subsymbol);
        goto exit;
    }
    if (!json_object_object_get_ex(jmember, "offset", &jvalue)) {
        dbprint(VMI_DEBUG_MISC, "Volatility IST profile: %s.%s has no offset defined\n", symbol, subsymbol);
        goto exit;
    }

    *rva = json_object_get_int64(jvalue);

    if (!json_object_object_get_ex(jmember, "type", &type)) {
        dbprint(VMI_DEBUG_MISC, "Volatility profile: no type found\n");
        goto exit;
    }

    if (!json_object_object_get_ex(type, "bit_position", &jvalue)) {
        dbprint(VMI_DEBUG_MISC, "Volatility profile: %s.%s has no member bit_position\n", symbol, subsymbol);
        goto exit;
    }
    *start_bit = json_object_get_int64(jvalue);

    if (!json_object_object_get_ex(type, "bit_length", &jvalue)) {
        dbprint(VMI_DEBUG_MISC, "Volatility profile: %s.%s has no member bit_length\n", symbol, subsymbol);
        goto exit;
    }
    size_t bit_length = json_object_get_int64(jvalue);
    *end_bit = *start_bit + bit_length;

    ret = VMI_SUCCESS;

exit:
    dbprint(VMI_DEBUG_MISC, "Volatility profile lookup %s %s: offset 0x%lx, start bit %ld, end bit %ld\n", symbol ?: NULL, subsymbol ?: NULL, *rva, *start_bit, *end_bit);

    return ret;
}

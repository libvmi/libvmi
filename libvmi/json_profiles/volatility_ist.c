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

// Perform recursive search for subsymbol under symbol
static status_t
volatility_ist_find_offset(
    json_object *json,
    const char *symbol,
    const char *subsymbol,
    addr_t *rva)
{
    status_t ret = VMI_FAILURE;
    json_object *user_types = NULL, *jstruct = NULL, *jstruct2 = NULL, *jmember = NULL, *jvalue = NULL;
    struct json_object_iterator iter, iend;

    if (!json_object_object_get_ex(json, "user_types", &user_types)) {
        dbprint(VMI_DEBUG_MISC, "Volatility IST profile: no user_types section found\n");
        goto exit;
    }
    if (!json_object_object_get_ex(user_types, symbol, &jstruct)) {
        dbprint(VMI_DEBUG_MISC, "Volatility IST profile: no %s found\n", symbol);
        goto exit;
    }

    if (!json_object_object_get_ex(jstruct, "fields", &jstruct2)) {
        dbprint(VMI_DEBUG_MISC, "Volatility IST profile: struct %s has no fields element\n", symbol);
        goto exit;
    }

    // check for terminal success case
    if (json_object_object_get_ex(jstruct2, subsymbol, &jmember)) {
        if (!json_object_object_get_ex(jmember, "offset", &jvalue)) {
            dbprint(VMI_DEBUG_MISC, "Volatility IST profile: %s.%s has no offset\n", symbol, subsymbol);
            goto exit;
        }
        ret = VMI_SUCCESS;
#ifdef JSONC_UINT64_SUPPORT
        *rva += json_object_get_uint64(jvalue);
#else
        *rva += json_object_get_int64(jvalue);
#endif
        goto exit;
    }

    // subsymbol not found; search down all anonymous or embedded structures in symbol.
    // example:
    // "mm_struct": {
    //   "size": 1032,
    //   "fields": {
    //     ...
    //     "unnamed_field_0": {
    //       "type": {
    //         "kind": "struct",
    //         "name": "unnamed_8216149fbf604e93"
    //       },
    //       "offset": 0,
    //       "anonymous": true
    //     }
    //   },
    //   "kind": "struct"
    // },

    iter = json_object_iter_begin (jstruct2);
    iend = json_object_iter_end (jstruct2);

    while (!json_object_iter_equal(&iter, &iend)) {
        json_object *subval = NULL, *subval2 = NULL, *subval3 = NULL;
        const char *subname1 = NULL;
        const char *embedded = NULL;

        subval = json_object_iter_peek_value(&iter);
        subname1 = json_object_iter_peek_name(&iter);
        (void) subname1; // only used in dprint

        // get the type dict for the subfield, e.g. "type": {"kind": "struct", "name": "unnamed_8216149fbf604e93" },
        if (!json_object_object_get_ex (subval, "type", &subval2))
            goto next;

        // get the name
        if (!json_object_object_get_ex (subval2, "name", &subval3))
            goto next;

        // finally, convert the object to a name
        embedded = json_object_get_string (subval3);
        if (!embedded)
            goto next;

        // now recurse into embedded, still looking for original subsymbol
        dbprint(VMI_DEBUG_MISC, "Volatility IST profile: exploring anonymous/embedded struct %s (%s) for offset for %s\n",
                subname1, embedded, subsymbol);
        ret = volatility_ist_find_offset(json, embedded, subsymbol, rva);
        if (VMI_SUCCESS == ret) {
            // the field was found in the anonymous struct. tack on that struct's offset; in example: 0.
            json_object *jofs = NULL;
            if (!json_object_object_get_ex(subval, "offset", &jofs)) {
                ret = VMI_FAILURE;
                dbprint(VMI_DEBUG_MISC, "Volatility IST profile: anonymous struct %s has no offset in %s\n", subname1, symbol);
                goto exit;
            }

#ifdef JSONC_UINT64_SUPPORT
            *rva += json_object_get_uint64(jofs);
#else
            *rva += json_object_get_int64(jofs);
#endif
            dbprint(VMI_DEBUG_MISC, "Volatility IST profile: %s.%s @ offset %ld\n", symbol, subname1, *rva);
            goto exit;
        }

next:
        json_object_iter_next (&iter);
    }


exit:
    return ret;
}

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

#ifdef JSONC_UINT64_SUPPORT
        *rva = json_object_get_uint64(address);
#else
        *rva = json_object_get_int64(address);
#endif
        ret = VMI_SUCCESS;
    } else {
        json_object *user_types = NULL, *jstruct = NULL;
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

#ifdef JSONC_UINT64_SUPPORT
            *size = json_object_get_uint64(jsize);
#else
            *size = json_object_get_int64(jsize);
#endif
            ret = VMI_SUCCESS;
            goto exit;
        }

        // look for offset by performing recursive search for subsymbol under symbol
        *rva = 0;
        ret = volatility_ist_find_offset(json, symbol, subsymbol, rva);
    }

exit:
    dbprint(VMI_DEBUG_MISC, "Volatility IST profile lookup %s %s: 0x%lx\n",
            symbol ?: NULL, subsymbol ?: NULL, rva ? *rva : 0);
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

#ifdef JSONC_UINT64_SUPPORT
    *rva = json_object_get_uint64(jvalue);
#else
    *rva = json_object_get_int64(jvalue);
#endif

    if (!json_object_object_get_ex(jmember, "type", &type)) {
        dbprint(VMI_DEBUG_MISC, "Volatility profile: no type found\n");
        goto exit;
    }

    if (!json_object_object_get_ex(type, "bit_position", &jvalue)) {
        dbprint(VMI_DEBUG_MISC, "Volatility profile: %s.%s has no member bit_position\n", symbol, subsymbol);
        goto exit;
    }

#ifdef JSONC_UINT64_SUPPORT
    *start_bit = json_object_get_uint64(jvalue);
#else
    *start_bit = json_object_get_int64(jvalue);
#endif

    if (!json_object_object_get_ex(type, "bit_length", &jvalue)) {
        dbprint(VMI_DEBUG_MISC, "Volatility profile: %s.%s has no member bit_length\n", symbol, subsymbol);
        goto exit;
    }

#ifdef JSONC_UINT64_SUPPORT
    size_t bit_length = json_object_get_uint64(jvalue);
#else
    size_t bit_length = json_object_get_int64(jvalue);
#endif

    *end_bit = *start_bit + bit_length;

    ret = VMI_SUCCESS;

exit:
    dbprint(VMI_DEBUG_MISC, "Volatility profile lookup %s %s: offset 0x%lx, start bit %ld, end bit %ld\n", symbol ?: NULL, subsymbol ?: NULL, *rva, *start_bit, *end_bit);

    return ret;
}

status_t
volatility_struct_field_type_name(
    json_object *json_profile,
    const char* struct_name,
    const char* field_name,
    const char** member_type_name)
{
    *member_type_name = NULL;

    struct json_object* json_user_types;
    if (!json_object_object_get_ex(json_profile, "user_types", &json_user_types)) {
        dbprint(VMI_DEBUG_MISC, "Volatility profile: no user_types section found.\n");
        return VMI_FAILURE;
    }

    struct json_object* json_struct;
    if (!json_object_object_get_ex(json_user_types, struct_name, &json_struct)) {
        dbprint(VMI_DEBUG_MISC, "Volatility IST profile: no %s found\n", struct_name);
        return VMI_FAILURE;
    }

    struct json_object* json_fields;
    if (!json_object_object_get_ex(json_struct, "fields", &json_fields)) {
        dbprint(VMI_DEBUG_MISC, "Volatility IST profile: %s has no `fields` key.\n", struct_name);
        return VMI_FAILURE;
    }

    struct json_object* json_field = NULL;
    if (!json_object_object_get_ex(json_fields, field_name, &json_field)) {
        // Check recursively all unnamed structure fields aswell, as many fields in linux are wrapped in anonymous structures for structure randomization.
        struct json_object_iterator it = json_object_iter_begin(json_fields);
        struct json_object_iterator it_end = json_object_iter_end(json_fields);
        for (; !json_object_iter_equal(&it, &it_end); json_object_iter_next(&it)) {
            if (strncmp(json_object_iter_peek_name(&it), "unnamed", strlen("unnamed")) != 0)
                continue;

            json_object* json_field_val = json_object_iter_peek_value(&it);

            struct json_object* json_field_subtype;
            if (!json_object_object_get_ex(json_field_val, "type", &json_field_subtype)) {
                dbprint(VMI_DEBUG_MISC, "Volatility IST profile: Failed to find `type` key.\n");
                return VMI_FAILURE;
            }

            struct json_object* json_field_subkind;
            if (!json_object_object_get_ex(json_field_subtype, "kind", &json_field_subkind)) {
                dbprint(VMI_DEBUG_MISC, "Volatility IST profile: Failed to find `kind` key.\n");
                return VMI_FAILURE;
            }
            if (strcmp(json_object_get_string(json_field_subkind), "struct") != 0)
                continue;

            struct json_object* json_anonymous_struct_name;
            if (!json_object_object_get_ex(json_field_subtype, "name", &json_anonymous_struct_name)) {
                dbprint(VMI_DEBUG_MISC, "Volatility IST profile: Failed to find `name` key\n");
                return VMI_FAILURE;
            }

            struct json_object *json_anonymous_struct;
            if (!json_object_object_get_ex(json_user_types, json_object_get_string(json_anonymous_struct_name), &json_anonymous_struct)) {
                dbprint(VMI_DEBUG_MISC, "Volatility IST profile: Failed to find %s in user_types.\n", json_object_get_string(json_anonymous_struct_name));
                return VMI_FAILURE;
            }

            struct json_object* json_anonymous_struct_fields;
            if (!json_object_object_get_ex(json_anonymous_struct, "fields", &json_anonymous_struct_fields)) {
                dbprint(VMI_DEBUG_MISC, "Volatility IST profile: Failed to find `fields` key.\n");
                return VMI_FAILURE;
            }

            if (json_object_object_get_ex(json_anonymous_struct_fields, field_name, &json_field))
                break;
        }
    }
    if (!json_field) {
        dbprint(VMI_DEBUG_MISC, "Volatility IST profile: Failed to find %s\n", field_name);
        return VMI_FAILURE;
    }

    struct json_object* json_struct_type;
    if (!json_object_object_get_ex(json_field, "type", &json_struct_type)) {
        dbprint(VMI_DEBUG_MISC, "Volatility IST profile: Failed to find `type` key.\n");
        return VMI_FAILURE;
    }

    struct json_object* json_type_name;
    if (!json_object_object_get_ex(json_struct_type, "name", &json_type_name)) {
        dbprint(VMI_DEBUG_MISC, "Volatility IST profile: Failed to find `name` key.\n");
        return VMI_FAILURE;
    }

    *member_type_name = json_object_get_string(json_type_name);
    return VMI_SUCCESS;
}

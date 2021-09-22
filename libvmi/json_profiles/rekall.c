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
rekall_find_offset(
    json_object *json,
    const char *symbol,
    const char *subsymbol,
    addr_t *rva)
{
    status_t ret = VMI_FAILURE;
    json_object *structs = NULL, *jstruct = NULL, *jstruct2 = NULL, *jmember = NULL, *jvalue = NULL;
    struct json_object_iterator iter, iend;

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

    // symbol.subsymbol is defined
    if (json_object_object_get_ex(jstruct2, subsymbol, &jmember)) {
        jvalue = json_object_array_get_idx(jmember, 0);
        if (!jvalue) {
            dbprint(VMI_DEBUG_MISC, "Rekall profile: %s.%s exists but has no RVA defined\n", symbol, subsymbol);
            goto exit;
        }
        // terminal success case
        ret = VMI_SUCCESS;
        *rva += json_object_get_int64(jvalue);
        dbprint(VMI_DEBUG_MISC, "Rekall profile: %s.%s @ offset 0x%lx\n", symbol, subsymbol, *rva);
        goto exit;
    }

    // subsymbol not found; search down all anonymous or embedded structures in symbol.
    // example: "mm_struct": [1032, {
    //                           ....
    //                        "u1": [0, ["__unnamed_178927"]] .... }]
    //           "__unnamed_178927": [1032, {
    //                           ....
    //                         "flags": [880, ["long unsigned int"]],
    //                           .... }]
    iter = json_object_iter_begin (jstruct2);
    iend = json_object_iter_end (jstruct2);

    while (!json_object_iter_equal(&iter, &iend)) {
        json_object *subval = NULL, *subval2 = NULL, *subval3 = NULL;
        const char *subname1 = NULL;
        const char *embedded = NULL;

        subval = json_object_iter_peek_value(&iter);
        subname1 = json_object_iter_peek_name(&iter);
        (void) subname1; // only used in dbprint()

        // get the top-level array from the value, e.g. ["__unnamed_178927"]
        subval2 = json_object_array_get_idx(subval, 1);
        if (!subval)
            goto next;

        // extract the name from the array, e.g. "__unnamed_178927"
        subval3 = json_object_array_get_idx(subval2, 0);
        if (!subval3)
            goto next;

        // finally, convert the object to a name
        embedded = json_object_get_string (subval3);
        if (!embedded)
            goto next;

        // now recurse into embedded, still looking for original subsymbol
        ret = rekall_find_offset (json, embedded, subsymbol, rva);
        if (VMI_SUCCESS == ret) {
            // the field was found in the anonymous struct. tack on that struct's offset; in example: 0.
            json_object *jofs = NULL;
            jofs = json_object_array_get_idx(subval, 0);
            if (!jofs) {
                ret = VMI_FAILURE;
                dbprint(VMI_DEBUG_MISC, "Rekall profile: anonymous/embedded struct %s has no offset in %s\n", subname1, symbol);
                goto exit;
            }

            *rva += json_object_get_int64(jofs);
            dbprint(VMI_DEBUG_MISC, "Rekall profile: %s.%s @ offset 0x%lx\n", symbol, subname1, *rva);
            goto exit;
        }

next:
        json_object_iter_next (&iter);
    }

exit:
    return ret;
}


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
        json_object *structs = NULL, *jstruct = NULL;

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

        // looking for offset, perform recursive search for subsymbol under symbol
        *rva = 0;
        ret = rekall_find_offset(json, symbol, subsymbol, rva);
    }

exit:
    dbprint(VMI_DEBUG_MISC, "Rekall profile lookup %s %s: 0x%lx\n", symbol ?: NULL, subsymbol ?: NULL, rva ? *rva : 0);

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

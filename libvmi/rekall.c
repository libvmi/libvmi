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
    const char *rekall_profile,
    const char *symbol,
    const char *subsymbol,
    addr_t *rva)
{
    status_t ret = VMI_FAILURE;
    if (!rekall_profile || !symbol) {
        return ret;
    }

    json_object *root = json_object_from_file(rekall_profile);
    if (!root) {
        errprint("Rekall profile couldn't be opened!\n");
        return ret;
    }

    if (!subsymbol) {
        json_object *constants = NULL, *functions = NULL, *jsymbol = NULL;
        if (json_object_object_get_ex(root, "$CONSTANTS", &constants)) {
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

        if (json_object_object_get_ex(root, "$FUNCTIONS", &functions)) {
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
        if (!json_object_object_get_ex(root, "$STRUCTS", &structs)) {
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
        ret = VMI_SUCCESS;
    }

exit:
    json_object_put(root);
    return ret;
}

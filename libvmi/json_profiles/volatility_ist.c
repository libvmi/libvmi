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
    json_object *root,
    const char *symbol,
    const char *subsymbol,
    addr_t *rva)
{
    status_t ret = VMI_FAILURE;
    if (!root || !symbol) {
        return ret;
    }

    if (!subsymbol) {
        json_object *symbols = NULL, *jsymbol = NULL, *address = NULL;
        if (!json_object_object_get_ex(root, "symbols", &symbols)) {
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
        if (!json_object_object_get_ex(root, "user_types", &user_types)) {
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

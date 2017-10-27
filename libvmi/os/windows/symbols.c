/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel (tamas.k.lengyel@tum.de)
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
#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#ifdef REKALL_PROFILES
#include <jansson.h>

status_t
windows_rekall_profile_symbol_to_rva(
    vmi_instance_t vmi,
    const char *symbol,
    const char *subsymbol,
    addr_t *rva)
{

    status_t ret = VMI_FAILURE;
    windows_instance_t windows = vmi->os_data;
    if (!windows || !symbol) {
        goto exit;
    }

    json_error_t error;
    json_t *root = json_load_file(windows->rekall_profile, 0, &error);
    if (!root) {
        errprint("Rekall profile error on line %d: %s\n", error.line, error.text);
        goto exit;
    }

    if (!json_is_object(root)) {
        errprint("Rekall profile: root is not an objet\n");
        goto err_exit;
    }

    if (!subsymbol) {
        json_t *constants = json_object_get(root, "$CONSTANTS");
        json_t *jsymbol = json_object_get(constants, symbol);
        if (!jsymbol) {
            dbprint(VMI_DEBUG_MISC, "Rekall profile: symbol '%s' not found\n", symbol);
            goto err_exit;
        }

        *rva = json_integer_value(jsymbol);
        ret = VMI_SUCCESS;

    } else {
        json_t *structs = json_object_get(root, "$STRUCTS");
        json_t *jstruct = json_object_get(structs, symbol);
        if (!jstruct) {
            dbprint(VMI_DEBUG_MISC, "Rekall profile: structure '%s' not found\n", symbol);
            goto err_exit;
        }

        json_t *jstruct2 = json_array_get(jstruct, 1);
        json_t *jmember = json_object_get(jstruct2, subsymbol);
        if (!jmember) {
            dbprint(VMI_DEBUG_MISC, "Rekall profile: structure member '%s' not found\n", subsymbol);
            goto err_exit;
        }
        json_t *jvalue = json_array_get(jmember, 0);

        *rva = json_integer_value(jvalue);
        ret = VMI_SUCCESS;

    }

err_exit:
    json_decref(root);

exit:
    return ret;
}

#else

status_t
windows_rekall_profile_symbol_to_rva(
    vmi_instance_t vmi,
    const char *symbol,
    const char *subsymbol,
    addr_t *rva)
{
    return VMI_FAILURE;
}

#endif

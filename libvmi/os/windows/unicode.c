/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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

#include <string.h>
#include <wchar.h>
#include <iconv.h>  // conversion between character sets
#include <errno.h>

#include "private.h"

unicode_string_t *
windows_read_unicode_struct(
    vmi_instance_t vmi,
    const access_context_t *ctx)
{
    access_context_t _ctx = *ctx;
    unicode_string_t *us = 0;   // return val
    size_t struct_size = 0;
    addr_t buffer_va = 0;
    uint16_t buffer_len = 0;

    if (VMI_PM_IA32E == vmi->page_mode) {   // 64 bit guest
        win64_unicode_string_t us64 = { 0 };
        struct_size = sizeof(us64);
        // read the UNICODE_STRING struct
        if ( VMI_FAILURE == vmi_read(vmi, ctx, struct_size, &us64, NULL) ) {
            dbprint(VMI_DEBUG_READ, "--%s: failed to read UNICODE_STRING\n",__FUNCTION__);
            goto out_error;
        }   // if
        buffer_va = us64.pBuffer;
        buffer_len = us64.length;
    } else {
        win32_unicode_string_t us32 = { 0 };
        struct_size = sizeof(us32);
        // read the UNICODE_STRING struct
        if ( VMI_FAILURE == vmi_read(vmi, ctx, struct_size, &us32, NULL) ) {
            dbprint(VMI_DEBUG_READ, "--%s: failed to read UNICODE_STRING\n",__FUNCTION__);
            goto out_error;
        }   // if
        buffer_va = us32.pBuffer;
        buffer_len = us32.length;
    }   // if-else

    if ( buffer_len > VMI_PS_4KB ) {
        dbprint(VMI_DEBUG_READ, "--%s: the length of %" PRIu16 " in the UNICODE_STRING at 0x%" PRIx64 " is excessive, bailing out.\n",
                __FUNCTION__, buffer_len, ctx->addr);
        return NULL;
    }

    // allocate the return value
    us = g_malloc0(sizeof(unicode_string_t));
    if ( !us )
        return NULL;

    us->length = buffer_len;
    us->contents = g_malloc0(sizeof(uint8_t) * (buffer_len + 2));

    if ( !us->contents )
        goto out_error;

    _ctx.addr = buffer_va;
    if ( VMI_FAILURE == vmi_read(vmi, &_ctx, us->length, us->contents, NULL) ) {
        dbprint(VMI_DEBUG_READ, "--%s: failed to read UNICODE_STRING buffer\n",__FUNCTION__);
        goto out_error;
    }   // if

    // end with NULL (needed?)
    us->contents[buffer_len] = 0;
    us->contents[buffer_len + 1] = 0;

    us->encoding = "UTF-16";

    return us;

out_error:
    if (us) g_free(us->contents);
    g_free(us);
    return 0;
}


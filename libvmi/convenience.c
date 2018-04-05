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

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <iconv.h>  // conversion between character sets

#include "private.h"

#ifndef VMI_DEBUG
/* Nothing */
#else
void
dbprint(
    vmi_debug_flag_t category,
    char *format,
    ...)
{
    if (category & VMI_DEBUG) {
        va_list args;

        va_start(args, format);
        vfprintf(stdout, format, args);
        va_end(args);
    }
}
#endif

/* prints an error message to stderr */
void
errprint(
    char *format,
    ...)
{
    va_list args;

    fprintf(stderr, "VMI_ERROR: ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

/* prints a warning message to stderr */
void
warnprint(
    char *format,
    ...)
{
    va_list args;

    fprintf(stderr, "VMI_WARNING: ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

void *
safe_malloc_(
    size_t size,
    char const *file,
    int line)
{
    void *p = malloc(size);

    if (NULL == p) {
        errprint("malloc %lu bytes failed at %s:%d\n",
                 (unsigned long) size, file, line);
        exit(EXIT_FAILURE);
    }
    return p;
}

unsigned long
get_reg32(
    reg_t r)
{
    return (unsigned long) r;
}

addr_t
aligned_addr(
    vmi_instance_t vmi,
    addr_t addr)
{
    addr_t mask = ~((addr_t) vmi->page_size - 1);
    addr_t aligned = (addr_t) addr & (addr_t) mask;

    return aligned;

}

int
is_addr_aligned(
    vmi_instance_t vmi,
    addr_t addr)
{
    return (addr == aligned_addr(vmi, addr));
}

status_t
vmi_convert_str_encoding(
    const unicode_string_t *in,
    unicode_string_t *out,
    const char *outencoding)
{
    iconv_t cd = 0;
    size_t iconv_val = 0;

    if (!in || !out)
        return VMI_FAILURE;

    size_t inlen = in->length;
    size_t outlen = 2 * (inlen + 1);

    char *incurr = (char*)in->contents;

    memset(out, 0, sizeof(*out));
    out->contents = safe_malloc(outlen);
    memset(out->contents, 0, outlen);

    char *outstart = (char*)out->contents;
    char *outcurr = (char*)out->contents;

    out->encoding = outencoding;

    cd = iconv_open(out->encoding, in->encoding);   // outset, inset
    if ((iconv_t) (-1) == cd) { // init failure
        if (EINVAL == errno) {
            dbprint(VMI_DEBUG_READ, "%s: conversion from '%s' to '%s' not supported\n",
                    __FUNCTION__, in->encoding, out->encoding);
        } else {
            dbprint(VMI_DEBUG_READ, "%s: Initializiation failure: %s\n", __FUNCTION__,
                    strerror(errno));
        }   // if-else
        goto fail;
    }   // if

    // init success

    iconv_val = iconv(cd, &incurr, &inlen, &outcurr, &outlen);
    if ((size_t) - 1 == iconv_val) {
        dbprint(VMI_DEBUG_READ, "%s: iconv failed, in string '%s' length %zu, "
                "out string '%s' length %zu\n", __FUNCTION__,
                in->contents, in->length, out->contents, outlen);
        switch (errno) {
            case EILSEQ:
                dbprint(VMI_DEBUG_READ, "invalid multibyte sequence");
                break;
            case EINVAL:
                dbprint(VMI_DEBUG_READ, "incomplete multibyte sequence");
                break;
            case E2BIG:
                dbprint(VMI_DEBUG_READ, "no more room");
                break;
            default:
                dbprint(VMI_DEBUG_READ, "error: %s\n", strerror(errno));
                break;
        }   // switch
        goto fail;
    }   // if failure

    // conversion success
    out->length = (size_t) (outcurr - outstart);
    (void) iconv_close(cd);
    return VMI_SUCCESS;

fail:
    if (out->contents) {
        free(out->contents);
    }
    // make failure really obvious
    memset(out, 0, sizeof(*out));

    if ((iconv_t) (-1) != cd) { // init succeeded
        (void) iconv_close(cd);
    }   // if

    return VMI_FAILURE;
}

void
vmi_free_unicode_str(
    unicode_string_t *p_us)
{
    if (!p_us)
        return;

    if (p_us->contents)
        free(p_us->contents);
    memset((void *) p_us, 0, sizeof(*p_us));
    free(p_us);
}

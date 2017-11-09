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

#define _GNU_SOURCE
#include <string.h>

#include "private.h"
#include "peparse.h"

void
dump_exports(
    vmi_instance_t vmi,
    struct export_table *et,
    const access_context_t *ctx)
{
    access_context_t _ctx = *ctx;
    addr_t base_addr = ctx->addr;
    addr_t base1 = base_addr + et->address_of_names;
    addr_t base2 = base_addr + et->address_of_name_ordinals;
    addr_t base3 = base_addr + et->address_of_functions;
    uint32_t i = 0;

    /* print names */
    for (; i < et->number_of_names; ++i) {
        uint32_t rva = 0;
        uint16_t ordinal = 0;
        uint32_t loc = 0;
        char *str = NULL;

        _ctx.addr = base1 + i * sizeof(uint32_t);
        if (VMI_FAILURE == vmi_read_32(vmi, &_ctx, &rva))
            continue;

        if (rva) {
            _ctx.addr = base_addr + rva;
            str = vmi_read_str(vmi, &_ctx);
            if (str) {
                _ctx.addr = base2 + i * sizeof(uint16_t);
                if (VMI_FAILURE == vmi_read_16(vmi, &_ctx, &ordinal)) {
                    free(str);
                    continue;
                }

                _ctx.addr = base3 + ordinal + sizeof(uint32_t);
                if (VMI_FAILURE == vmi_read_32(vmi, &_ctx, &loc)) {
                    free(str);
                    continue;
                }

                printf("%s:%d:0x%"PRIx32"\n", str, ordinal, loc);
                free(str);
            }
        }
    }
}

status_t
get_export_rva(
    vmi_instance_t vmi,
    addr_t *rva,
    int aof_index,
    struct export_table *et,
    const access_context_t *ctx)
{
    access_context_t _ctx = *ctx;
    _ctx.addr += et->address_of_functions + aof_index * sizeof(uint32_t);

    uint32_t tmp = 0;
    if (VMI_SUCCESS == vmi_read_32(vmi, &_ctx, &tmp)) {
        *rva = (addr_t) tmp;
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

int
get_aof_index(
    vmi_instance_t vmi,
    int aon_index,
    struct export_table *et,
    const access_context_t *ctx)
{
    access_context_t _ctx = *ctx;
    _ctx.addr += et->address_of_name_ordinals + aon_index * sizeof(uint16_t);

    uint16_t aof_index;
    if (VMI_SUCCESS == vmi_read_16(vmi, &_ctx, &aof_index))
        return (int) aof_index;
    else
        return -1;
}

// Finds the index of the exported symbol specified - linear search
int
get_aon_index_linear(
    vmi_instance_t vmi,
    const char *symbol,
    struct export_table *et,
    const access_context_t *ctx)
{
    access_context_t _ctx = *ctx;
    uint32_t i = 0;

    for (; i < et->number_of_names; ++i) {
        _ctx.addr = ctx->addr + et->address_of_names + i * sizeof(uint32_t);
        uint32_t str_rva = 0;

        if (VMI_SUCCESS == vmi_read_32(vmi, &_ctx, &str_rva) && str_rva) {
            _ctx.addr = ctx->addr+str_rva;
            char *rva = vmi_read_str(vmi, &_ctx);

            if (NULL != rva) {
                if (strncmp(rva, symbol, strlen(rva)) == 0) {
                    free(rva);
                    return (int) i;
                }
            }
            free(rva);
        }
    }

    /* didn't find anything that matched */
    return -1;
}

// binary search function for get_aon_index_binary()
static int
find_aon_idx_bin(
    vmi_instance_t vmi,
    const char *symbol,
    addr_t aon_base_va,
    int low,
    int high,
    const access_context_t *ctx)
{
    access_context_t _ctx = *ctx;
    int mid, cmp;
    uint32_t str_rva = 0;   // RVA of curr name
    char *name = 0; // curr name

    if (high < low)
        goto not_found;

    // calc the current index ("mid")
    mid = (low + high) / 2;

    _ctx.addr = aon_base_va + mid * sizeof(uint32_t);
    if (VMI_FAILURE == vmi_read_32(vmi, &_ctx, &str_rva) || !str_rva)
        goto not_found;

    // get the curr string & compare to symbol
    _ctx.addr = ctx->addr + str_rva;
    name = vmi_read_str(vmi, &_ctx);
    if (!name)
        goto not_found;

    cmp = strcmp(symbol, name);
    free(name);

    if (cmp < 0) {  // symbol < name ==> try lower region
        return find_aon_idx_bin(vmi, symbol, aon_base_va, low, mid - 1, ctx);
    } else if (cmp > 0) { // symbol > name ==> try higher region
        return find_aon_idx_bin(vmi, symbol, aon_base_va, mid + 1, high, ctx);
    } else { // symbol == name
        return mid; // found
    }

not_found:
    return -1;
}

// Finds the index of the exported symbol specified - binary search
int
get_aon_index_binary(
    vmi_instance_t vmi,
    const char *symbol,
    struct export_table *et,
    const access_context_t *ctx)
{
    addr_t aon_base_addr = ctx->addr + et->address_of_names;
    int name_ct = et->number_of_names;

    return find_aon_idx_bin(vmi, symbol, aon_base_addr, 0, name_ct - 1, ctx);
}

int
get_aon_index(
    vmi_instance_t vmi,
    const char *symbol,
    struct export_table *et,
    const access_context_t *ctx)
{
    int index = get_aon_index_binary(vmi, symbol, et, ctx);

    if (-1 == index) {
        dbprint
        (VMI_DEBUG_PEPARSE, "--PEParse: Falling back to linear search for aon index\n");
        // This could be useful for malformed PE headers where the list isn't
        // in alpha order (e.g., malware)
        index = get_aon_index_linear(vmi, symbol, et, ctx);
    }
    return index;
}

status_t
peparse_validate_pe_image(
    const uint8_t * const image,
    size_t len)
{
    struct dos_header *dos_header = (struct dos_header *) image;
    uint32_t fixed_header_sz =
        sizeof(struct optional_header_pe32plus) +
        sizeof(struct pe_header);

    //vmi_print_hex (image, MAX_HEADER_BYTES);

    if (IMAGE_DOS_HEADER != dos_header->signature) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEPARSE: DOS header signature not found\n");
        return VMI_FAILURE;
    }

    uint32_t ofs_to_pe = dos_header->offset_to_pe;

    if (ofs_to_pe > len - fixed_header_sz) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEPARSE: DOS header offset to PE value too big\n");
        return VMI_FAILURE;
    }

    struct pe_header *pe_header =
        (struct pe_header *) (image + ofs_to_pe);
    if (IMAGE_NT_SIGNATURE != pe_header->signature) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEPARSE: PE header signature invalid\n");
        return VMI_FAILURE;
    }

    // just get the magic # - we don't care here whether its PE or PE+
    struct optional_header_pe32 *pe_opt_header =
        (struct optional_header_pe32 *)
        ((uint8_t *) pe_header + sizeof(struct pe_header));

    if (IMAGE_PE32_MAGIC != pe_opt_header->magic &&
            IMAGE_PE32_PLUS_MAGIC != pe_opt_header->magic) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEPARSE: Optional header magic value unknown\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t
peparse_get_image(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t len,
    const uint8_t * const image)
{
    if ( VMI_FAILURE == vmi_read(vmi, ctx, len, (void *)image, NULL) ) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEPARSE: failed to read PE header\n");
        return VMI_FAILURE;
    }

    if (VMI_SUCCESS != peparse_validate_pe_image(image, len)) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEPARSE: failed to validate PE header(s)\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

void
peparse_assign_headers(
    const uint8_t * const image,
    struct dos_header **dos_header,
    struct pe_header **pe_header,
    uint16_t *optional_header_type,
    void **optional_pe_header,
    struct optional_header_pe32 **oh_pe32,
    struct optional_header_pe32plus **oh_pe32plus)
{

    struct dos_header *dos_h_t = (struct dos_header *) image;
    if (dos_header != NULL) {
        *dos_header=dos_h_t;
    }

    struct pe_header *pe_h_t = (struct pe_header *) (image + dos_h_t->offset_to_pe);
    if (pe_header != NULL) {
        *pe_header=pe_h_t;
    }

    void *op_h_t = (void *) ((uint8_t *) pe_h_t + sizeof(struct pe_header));
    if (optional_pe_header != NULL) {
        *optional_pe_header = op_h_t;
    }

    uint16_t magic = *((uint16_t *) op_h_t);
    if (optional_header_type != NULL) {
        *optional_header_type = magic;
    }

    dbprint(VMI_DEBUG_PEPARSE, "--PEParse: magic is 0x%"PRIx16"\n", magic);

    if (magic == IMAGE_PE32_MAGIC && oh_pe32 != NULL) {
        *oh_pe32 = (struct optional_header_pe32 *) op_h_t;
    } else if (magic == IMAGE_PE32_PLUS_MAGIC && oh_pe32plus != NULL) {
        *oh_pe32plus = (struct optional_header_pe32plus *) op_h_t;
    }
}

addr_t
peparse_get_idd_rva(
    uint32_t entry_id,
    uint16_t *optional_header_type,
    void *optional_header,
    struct optional_header_pe32 *oh_pe32,
    struct optional_header_pe32plus *oh_pe32plus)
{

    addr_t rva = 0;

    if (optional_header_type == NULL) {

        if (oh_pe32 != NULL && oh_pe32->number_of_rva_and_sizes >= entry_id) {
            rva = oh_pe32->idd[entry_id].virtual_address;
            goto done;
        }

        if (oh_pe32plus != NULL && oh_pe32plus->number_of_rva_and_sizes >= entry_id) {
            rva = oh_pe32plus->idd[entry_id].virtual_address;
            goto done;
        }
    } else if (optional_header) {

        switch ( *optional_header_type ) {
            case IMAGE_PE32_MAGIC: {
                struct optional_header_pe32 *oh_pe32_t = (struct optional_header_pe32 *)optional_header;
                if (oh_pe32_t->number_of_rva_and_sizes >= entry_id) {
                    rva = oh_pe32_t->idd[entry_id].virtual_address;
                }
                break;
            }

            case IMAGE_PE32_PLUS_MAGIC: {
                struct optional_header_pe32plus *oh_pe32plus_t = (struct optional_header_pe32plus *)optional_header;
                if (oh_pe32plus_t->number_of_rva_and_sizes >= entry_id) {
                    rva = oh_pe32plus_t->idd[entry_id].virtual_address;
                }
                break;
            }

            default:
                break;
        }
    }

done:
    if (rva == 0) {
        // Could this be legit? If not, we might want to switch this to a status_t function
        dbprint(VMI_DEBUG_PEPARSE, "--PEParse: Image data directory RVA is 0\n");
    }

    return rva;
}

size_t
peparse_get_idd_size(
    uint32_t entry_id,
    uint16_t *optional_header_type,
    void *optional_header,
    struct optional_header_pe32 *oh_pe32,
    struct optional_header_pe32plus *oh_pe32plus)
{

    size_t size = 0;

    if (optional_header_type == NULL) {

        if (oh_pe32 != NULL) {
            size = oh_pe32->idd[entry_id].size;
            goto done;
        }

        if (oh_pe32plus != NULL) {
            size = oh_pe32plus->idd[entry_id].size;
            goto done;
        }
    } else if (optional_header != NULL) {

        if (*optional_header_type == IMAGE_PE32_MAGIC) {
            struct optional_header_pe32 *oh_pe32_t = (struct optional_header_pe32 *)optional_header;
            size = oh_pe32_t->idd[entry_id].size;
            goto done;
        }

        if (*optional_header_type == IMAGE_PE32_PLUS_MAGIC) {
            struct optional_header_pe32plus *oh_pe32plus_t = (struct optional_header_pe32plus *)optional_header;
            size = oh_pe32plus_t->idd[entry_id].size;
            goto done;
        }
    }

done:
    return size;
}

status_t
peparse_get_export_table(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    struct export_table *et,
    addr_t *export_table_rva,
    size_t *export_table_size)
{
    // Note: this function assumes a "normal" PE where all the headers are in
    // the first page of the PE and the field DosHeader.OffsetToPE points to
    // an address in the first page.

    access_context_t _ctx = *ctx;
    addr_t export_header_rva = 0;
    size_t export_header_size = 0;

#define MAX_HEADER_BYTES 1024   // keep under 1 page
    uint8_t image[MAX_HEADER_BYTES];

    if (VMI_FAILURE == peparse_get_image(vmi, ctx, MAX_HEADER_BYTES, image)) {
        return VMI_FAILURE;
    }

    void *optional_header = NULL;
    uint16_t magic = 0;

    peparse_assign_headers(image, NULL, NULL, &magic, &optional_header, NULL, NULL);
    export_header_rva = peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_EXPORT, &magic, optional_header, NULL, NULL);
    export_header_size = peparse_get_idd_size(IMAGE_DIRECTORY_ENTRY_EXPORT, &magic, optional_header, NULL, NULL);

    if (export_table_rva) {
        *export_table_rva=export_header_rva;
    }

    if (export_table_size) {
        *export_table_size=export_header_size;
    }

    dbprint(VMI_DEBUG_PEPARSE, "--PEParse: DLL base 0x%.16"PRIx64". Export header [RVA] 0x%.16"PRIx64". Size %" PRIu64 ".\n",
            ctx->addr, export_header_rva, export_header_size);

    _ctx.addr = ctx->addr + export_header_rva;
    if ( VMI_FAILURE == vmi_read(vmi, &_ctx,  sizeof(struct export_table), et, NULL) ) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEParse: failed to map export header\n");

        /*
         * Sometimes Windows maps the export table on page-boundaries,
         * such that the first export_flags field (which is reserved) is.
         * not actually accessible (the page is not mapped). See Issue #260.
         */
        if (!((_ctx.addr+4) & 0xfff)) {
            dbprint(VMI_DEBUG_PEPARSE, "--PEParse: export table is mapped on page boundary\n");
            _ctx.addr += 4;
            if ( VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(struct export_table)-4, (void*)((char*)et+4), NULL) ) {
                dbprint(VMI_DEBUG_PEPARSE, "--PEParse: still failed to map export header\n");
                return VMI_FAILURE;
            }

            // Manually set the reserved field to zero in this case
            et->export_flags = 0;
        } else {
            return VMI_FAILURE;
        }
    }

    /* sanity check */
    if (et->export_flags || !et->name) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEParse: bad export directory table\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

/* returns the rva value for a windows PE export */
status_t
windows_export_to_rva(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    const char *symbol,
    addr_t *rva)
{
    struct export_table et;
    addr_t et_rva;
    size_t et_size;
    int aon_index = -1;
    int aof_index = -1;

    // get export table structure
    if (peparse_get_export_table(vmi, ctx, &et, &et_rva, &et_size) != VMI_SUCCESS) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEParse: failed to get export table\n");
        return VMI_FAILURE;
    }

    // find AddressOfNames index for export symbol
    aon_index = get_aon_index(vmi, symbol, &et, ctx);
    if ( -1 == aon_index ) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEParse: failed to get aon index\n");
        return VMI_FAILURE;
    }

    // find AddressOfFunctions index for export symbol
    aof_index = get_aof_index(vmi, aon_index, &et, ctx);
    if ( -1 == aof_index ) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEParse: failed to get aof index\n");
        return VMI_FAILURE;
    }

    // find RVA value for export symbol
    if (VMI_SUCCESS==get_export_rva(vmi, rva, aof_index, &et, ctx)) {

        // handle forwarded functions
        // If the function's RVA is inside the exports section (as given by the
        // VirtualAddress and Size fields in the idd), the symbol is forwarded.
        if (*rva>=et_rva && *rva < et_rva+et_size) {
            dbprint(VMI_DEBUG_PEPARSE, "--PEParse: %s @ 0x%p is forwarded\n", symbol, ctx);
            return VMI_FAILURE;
        } else {
            return VMI_SUCCESS;
        }
    } else {
        return VMI_FAILURE;
    }
}

/* returns a windows PE export from an RVA*/
char*
windows_rva_to_export(
    vmi_instance_t vmi,
    addr_t rva,
    const access_context_t *ctx)
{
    access_context_t _ctx = *ctx;
    struct export_table et;
    addr_t et_rva;
    size_t et_size;

    // get export table structure
    if (peparse_get_export_table(vmi, ctx, &et, &et_rva, &et_size) != VMI_SUCCESS) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEParse: failed to get export table\n");
        return NULL;
    }

    if (rva>=et_rva && rva < et_rva+et_size) {
        dbprint(VMI_DEBUG_PEPARSE, "--PEParse: symbol @ 0x%"PRIx64" is forwarded\n", ctx->addr+rva);
        return NULL;
    }


    addr_t base1 = ctx->addr + et.address_of_names;
    addr_t base2 = ctx->addr + et.address_of_name_ordinals;
    addr_t base3 = ctx->addr + et.address_of_functions;
    uint32_t i = 0;

    for (; i < et.number_of_functions; ++i) {
        uint32_t name_rva = 0;
        uint16_t ordinal = 0;
        uint32_t loc = 0;

        _ctx.addr = base2 + i * sizeof(uint16_t);
        if (VMI_FAILURE==vmi_read_16(vmi, &_ctx, &ordinal))
            continue;

        _ctx.addr = base3 + ordinal * sizeof(uint32_t);
        if (VMI_FAILURE==vmi_read_32(vmi, &_ctx, &loc))
            continue;

        if (loc==rva) {

            _ctx.addr = base1 + i * sizeof(uint32_t);
            if (i < et.number_of_names && VMI_SUCCESS==vmi_read_32(vmi, &_ctx, &name_rva) && name_rva) {
                _ctx.addr = ctx->addr + name_rva;
                return vmi_read_str(vmi, &_ctx);
            }

            dbprint(VMI_DEBUG_PEPARSE, "--PEParse: symbol @ 0x%"PRIx64" is exported by ordinal only\n", ctx->addr+rva);
            break;
        }
    }

    return NULL;
}



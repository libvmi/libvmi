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

#include "libvmi.h"
#include "peparse.h"
#include "private.h"
#define _GNU_SOURCE
#include <string.h>

// takes an rva and looks up a null terminated string at that location
char *
rva_to_string(
    vmi_instance_t vmi,
    addr_t rva)
{
    addr_t vaddr = vmi->os.windows_instance.ntoskrnl_va + rva;

    return vmi_read_str_va(vmi, vaddr, 0);
}

void
dump_exports(
    vmi_instance_t vmi,
    struct export_table *et)
{
    uint32_t base_addr = vmi->os.windows_instance.ntoskrnl_va;
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

        vmi_read_32_va(vmi, base1 + i * sizeof(uint32_t), 0, &rva);
        if (rva) {
            str = rva_to_string(vmi, (addr_t) rva);
            if (str) {
                vmi_read_16_va(vmi, base2 + i * sizeof(uint16_t), 0,
                               &ordinal);
                vmi_read_32_va(vmi, base3 + ordinal + sizeof(uint32_t),
                               0, &loc);
                printf("%s:%d:0x%x\n", str, ordinal, loc);
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
    struct export_table *et)
{
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl_va;
    addr_t rva_loc =
        base_addr + et->address_of_functions +
        aof_index * sizeof(uint32_t);

    uint32_t tmp = 0;
    status_t ret = vmi_read_32_va(vmi, rva_loc, 0, &tmp);

    *rva = (addr_t) tmp;
    return ret;
}

int
get_aof_index(
    vmi_instance_t vmi,
    int aon_index,
    struct export_table *et)
{
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl_va;
    addr_t aof_index_loc =
        base_addr + et->address_of_name_ordinals +
        aon_index * sizeof(uint16_t);
    uint32_t aof_index = 0;

    if (vmi_read_32_va(vmi, aof_index_loc, 0, &aof_index) ==
        VMI_SUCCESS) {
        return (int) (aof_index & 0xffff);
    }
    else {
        return -1;
    }
}

// Finds the index of the exported symbol specified - linear search
int
get_aon_index_linear(
    vmi_instance_t vmi,
    char *symbol,
    struct export_table *et)
{
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl_va;
    uint32_t i = 0;

    for (; i < et->number_of_names; ++i) {
        addr_t str_rva_loc =
            base_addr + et->address_of_names + i * sizeof(uint32_t);
        uint32_t str_rva = 0;

        vmi_read_32_va(vmi, str_rva_loc, 0, &str_rva);
        if (str_rva) {
            char *rva = rva_to_string(vmi, (addr_t) str_rva);

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
    char *symbol,
    addr_t aon_base_va,
    int low,
    int high)
{
    int mid, cmp;
    addr_t str_rva_loc; // location of curr name's RVA
    uint32_t str_rva;   // RVA of curr name
    char *name = 0; // curr name

    if (high < low)
        goto not_found;

    // calc the current index ("mid")
    mid = (low + high) / 2;
    str_rva_loc = aon_base_va + mid * sizeof(uint32_t);

    vmi_read_32_va(vmi, str_rva_loc, 0, &str_rva);

    if (!str_rva)
        goto not_found;

    // get the curr string & compare to symbol
    name = rva_to_string(vmi, (addr_t) str_rva);
    cmp = strcmp(symbol, name);
    free(name);

    if (cmp < 0) {  // symbol < name ==> try lower region
        return find_aon_idx_bin(vmi, symbol, aon_base_va, low, mid - 1);
    }
    else if (cmp > 0) { // symbol > name ==> try higher region
        return find_aon_idx_bin(vmi, symbol, aon_base_va, mid + 1,
                                high);
    }
    else {  // symbol == name
        return mid; // found
    }

not_found:
    return -1;
}

// Finds the index of the exported symbol specified - binary search
int
get_aon_index_binary(
    vmi_instance_t vmi,
    char *symbol,
    struct export_table *et)
{
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl_va;
    addr_t aon_base_addr = base_addr + et->address_of_names;
    int name_ct = et->number_of_names;

    return find_aon_idx_bin(vmi, symbol, aon_base_addr, 0, name_ct - 1);
}

int
get_aon_index(
    vmi_instance_t vmi,
    char *symbol,
    struct export_table *et)
{
    int index = get_aon_index_binary(vmi, symbol, et);

    if (-1 == index) {
        dbprint
            ("--PEParse: Falling back to linear search for aon index\n");
        // This could be useful for malformed PE headers where the list isn't
        // in alpha order (e.g., malware)
        index = get_aon_index_linear(vmi, symbol, et);
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
        dbprint("--PEPARSE: DOS header signature not found\n");
        return VMI_FAILURE;
    }

    uint32_t ofs_to_pe = dos_header->offset_to_pe;

    if (ofs_to_pe > len - fixed_header_sz) {
        dbprint("--PEPARSE: DOS header offset to PE value too big\n");
        return VMI_FAILURE;
    }

    struct pe_header *pe_header =
        (struct pe_header *) (image + ofs_to_pe);
    if (IMAGE_NT_SIGNATURE != pe_header->signature) {
        dbprint("--PEPARSE: PE header signature invalid\n");
        return VMI_FAILURE;
    }

    // just get the magic # - we don't care here whether its PE or PE+
    struct optional_header_pe32 *pe_opt_header =
        (struct optional_header_pe32 *)
        ((uint8_t *) pe_header + sizeof(struct pe_header));

    if (IMAGE_PE32_MAGIC != pe_opt_header->magic &&
        IMAGE_PE32_PLUS_MAGIC != pe_opt_header->magic) {
        dbprint("--PEPARSE: Optional header magic value unknown\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t
peparse_get_export_table(
    vmi_instance_t vmi,
    addr_t base_vaddr,
    uint32_t pid,
    struct export_table *et)
{
    // Note: this function assumes a "normal" PE where all the headers are in
    // the first page of the PE and the field DosHeader.OffsetToPE points to
    // an address in the first page.

    addr_t export_header_rva = 0;
    addr_t export_header_va = 0;
    size_t nbytes = 0;

#define MAX_HEADER_BYTES 1024   // keep under 1 page
    uint8_t image[MAX_HEADER_BYTES];

    /* scoop up the headers in a single read */
    nbytes = vmi_read_va(vmi, base_vaddr, pid, image, MAX_HEADER_BYTES);
    if (MAX_HEADER_BYTES != nbytes) {
        dbprint("--PEPARSE: failed to read PE header\n");
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == peparse_validate_pe_image(image, MAX_HEADER_BYTES)) {
        dbprint("--PEPARSE: failed to validate PE header(s)\n");
        return VMI_FAILURE;
    }

    /* Get basic data from the headers */
    struct dos_header *dos_header = (struct dos_header *) image;
    struct pe_header *pe_header =
        (struct pe_header *) (image + dos_header->offset_to_pe);

    /* read ahead to the ext pe header signature */
    void *pv_optional_pe_header =
        (void *) ((uint8_t *) pe_header + sizeof(struct pe_header));

    uint16_t magic = *((uint16_t *) pv_optional_pe_header);

    dbprint("--PEParse: magic is 0x%x\n", magic);

    if (IMAGE_PE32_MAGIC == magic) {
        struct optional_header_pe32 *oh =
            (struct optional_header_pe32 *) pv_optional_pe_header;
        export_header_rva =
            (addr_t) oh->idd[IMAGE_DIRECTORY_ENTRY_EXPORT].
            virtual_address;
    }
    else {  // must be IMAGE_PE32_PLUS_MAGIC -- see validate_pe_image()
        struct optional_header_pe32plus *oh =
            (struct optional_header_pe32plus *) pv_optional_pe_header;
        export_header_rva =
            (addr_t) oh->idd[IMAGE_DIRECTORY_ENTRY_EXPORT].
            virtual_address;
    }

    /* Find & read the export header; assume a different page than the headers */
    export_header_va = base_vaddr + export_header_rva;
    dbprint
        ("--PEParse: found export table at [VA] 0x%.16llx = 0x%.16llx + 0x%x\n",
         export_header_va, vmi->os.windows_instance.ntoskrnl_va,
         export_header_rva);

    nbytes = vmi_read_va(vmi, export_header_va, pid, et, sizeof(*et));
    if (nbytes != sizeof(struct export_table)) {
        dbprint("--PEParse: failed to map export header\n");
        return VMI_FAILURE;
    }

    /* sanity check */
    if (et->export_flags || !et->name) {
        dbprint("--PEParse: bad export directory table\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

/* returns the rva value for a windows kernel export */
status_t
windows_export_to_rva(
    vmi_instance_t vmi,
    char *symbol,
    addr_t *rva)
{
    struct export_table et;
    int aon_index = -1;
    int aof_index = -1;
    addr_t base_vaddr = vmi->os.windows_instance.ntoskrnl_va;

    // get export table structure
    if (peparse_get_export_table(vmi, base_vaddr, 0, &et) != VMI_SUCCESS) {
        dbprint("--PEParse: failed to get export table\n");
        return VMI_FAILURE;
    }

    // find AddressOfNames index for export symbol
    if ((aon_index = get_aon_index(vmi, symbol, &et)) == -1) {
        dbprint("--PEParse: failed to get aon index\n");
        return VMI_FAILURE;
    }

    // find AddressOfFunctions index for export symbol
    if ((aof_index = get_aof_index(vmi, aon_index, &et)) == -1) {
        dbprint("--PEParse: failed to get aof index\n");
        return VMI_FAILURE;
    }

    // find RVA value for export symbol
    return get_export_rva(vmi, rva, aof_index, &et);
}

/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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
#include "private.h"
#define _GNU_SOURCE
#include <string.h>

#define IMAGE_DOS_HEADER 0x5A4D // ZM
#define IMAGE_NT_SIGNATURE 0x00004550 // 00EP

#define IMAGE_PE32_MAGIC      0x10b
#define IMAGE_PE32_PLUS_MAGIC 0x20b

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_CERTIFICATE 4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_CLR_RUNTIME 14
#define IMAGE_DIRECTORY_ENTRY_RESERVED 15

struct image_data_directory{
    uint32_t virtual_address;
    uint32_t size;
} __attribute__ ((packed));

struct pe_header{
    int32_t signature;
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
    // characteristics flags defined in pe.txt
} __attribute__ ((packed));

struct dos_header {
    uint16_t signature;
    uint16_t bytes_in_last_block;
    uint16_t blocks_in_file;
    uint16_t reloc_ct;
    uint16_t header_size;
    uint16_t min_mem;
    uint16_t max_mem;
    uint16_t ss;
    uint16_t sp;
    uint16_t chksum;
    uint16_t ip;
    uint16_t cs;
    uint16_t reloc_tbl_ofs;
    uint16_t overlay;
    uint8_t  reserved[32];
    uint32_t offset_to_pe;
} __attribute__ ((packed));

struct optional_header_pe32{
    uint16_t magic; // 0x10b
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve; 
    uint32_t size_of_stack_commit; 
    uint32_t size_of_heap_reserve; 
    uint32_t size_of_heap_commit; 
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    struct image_data_directory idd[16];
} __attribute__ ((packed));

struct optional_header_pe32plus{
    uint16_t magic; // 0x20b
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve; 
    uint64_t size_of_stack_commit; 
    uint64_t size_of_heap_reserve; 
    uint64_t size_of_heap_commit; 
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    struct image_data_directory idd[16];
} __attribute__ ((packed));

struct section_header{
    char short_name[8];
    union{
        uint32_t physical_address;
        uint32_t virtual_size;
    } a;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_line_numbers;
    uint16_t number_of_relocations;
    uint16_t number_of_line_numbers;
    uint32_t characteristics;
} __attribute__ ((packed));

struct export_table{
    uint32_t export_flags; // reserved, must be 0
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name;
    uint32_t base;
    uint32_t number_of_functions;  // total number of exported items
    uint32_t number_of_names;
    uint32_t address_of_functions;
    uint32_t address_of_names;
    uint32_t address_of_name_ordinals;
} __attribute__ ((packed));

// takes an rva and looks up a null terminated string at that location
char *rva_to_string (vmi_instance_t vmi, addr_t rva)
{
    addr_t vaddr = vmi->os.windows_instance.ntoskrnl_va + rva;
    return vmi_read_str_va(vmi, vaddr, 0);
}

void dump_exports (vmi_instance_t vmi, struct export_table * et)
{
    uint32_t base_addr = vmi->os.windows_instance.ntoskrnl_va;
    addr_t base1 = base_addr + et->address_of_names;
    addr_t base2 = base_addr + et->address_of_name_ordinals;
    addr_t base3 = base_addr + et->address_of_functions;
    uint32_t i = 0;

    /* print names */
    for ( ; i < et->number_of_names; ++i){
        uint32_t rva = 0;
        uint16_t ordinal = 0;
        uint32_t loc = 0;
        char *str = NULL;
        vmi_read_32_va(vmi, base1 + i * sizeof(uint32_t), 0, &rva);
        if (rva){
            str = rva_to_string(vmi, (addr_t) rva);
            if (str){
                vmi_read_16_va(vmi, base2 + i * sizeof(uint16_t), 0, &ordinal);
                vmi_read_32_va(vmi, base3 + ordinal + sizeof(uint32_t), 0, &loc);
                printf("%s:%d:0x%x\n", str, ordinal, loc);
                free(str);
            }
        }
    }
}

status_t get_export_rva (
        vmi_instance_t vmi, addr_t *rva,
        int aof_index, struct export_table *et)
{
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl_va;
    addr_t rva_loc =
        base_addr + et->address_of_functions + aof_index * sizeof(uint32_t);

    uint32_t tmp = 0;
    status_t ret = vmi_read_32_va(vmi, rva_loc, 0, &tmp);
    *rva = (addr_t) tmp;
    return ret;
}

int get_aof_index (
        vmi_instance_t vmi, int aon_index, struct export_table *et)
{
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl_va;
    addr_t aof_index_loc =
        base_addr + et->address_of_name_ordinals + aon_index * sizeof(uint16_t);
    uint32_t aof_index = 0;

    if (vmi_read_32_va(vmi, aof_index_loc, 0, &aof_index) == VMI_SUCCESS){
        return (int) (aof_index & 0xffff);
    }
    else{
        return -1;
    }
}

// Finds the index of the exported symbol specified - linear search
int get_aon_index_linear (vmi_instance_t vmi, char *symbol, struct export_table *et)
{
    /*TODO implement faster name search alg since names are sorted */
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl_va;
    uint32_t i = 0;

    for ( ; i < et->number_of_names; ++i){
        addr_t str_rva_loc = base_addr + et->address_of_names + i * sizeof(uint32_t);
        uint32_t str_rva = 0;
        vmi_read_32_va(vmi, str_rva_loc, 0, &str_rva);
        if (str_rva){
            char *rva = rva_to_string(vmi, (addr_t) str_rva);
            if (NULL != rva){
                if (strncmp(rva, symbol, strlen(rva)) == 0){
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
static int find_aon_idx_bin (vmi_instance_t vmi, 
                             char *symbol,
                             addr_t aon_base_va,
                             int low,
                             int high            )
{
    int mid, cmp;
    addr_t str_rva_loc;   // location of curr name's RVA
    uint32_t str_rva;     // RVA of curr name
    char * name = 0;      // curr name

    if (high < low) goto not_found;

    // calc the current index ("mid")
    mid = (low + high) / 2;
    str_rva_loc = aon_base_va + mid * sizeof(uint32_t);

    vmi_read_32_va (vmi, str_rva_loc, 0, &str_rva);

    if (!str_rva) goto not_found;

    // get the curr string & compare to symbol
    name = rva_to_string (vmi, (addr_t)str_rva);
    cmp = strcmp (symbol, name);
    free (name);

    if (cmp < 0) { // symbol < name ==> try lower region
        return find_aon_idx_bin (vmi, symbol, aon_base_va, low, mid-1);
    } else if (cmp > 0) { // symbol > name ==> try higher region
        return find_aon_idx_bin (vmi, symbol, aon_base_va, mid+1, high);
    } else { // symbol == name
        return mid; // found
    }

not_found:
    return -1;
}

// Finds the index of the exported symbol specified - binary search
int get_aon_index_binary (vmi_instance_t vmi, char *symbol, struct export_table *et)
{
    /*TODO implement faster name search alg since names are sorted */
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl_va;
    addr_t aon_base_addr = base_addr + et->address_of_names;
    int    name_ct  = et->number_of_names;

    return find_aon_idx_bin (vmi, symbol, aon_base_addr, 0, name_ct-1);
}


status_t validate_pe_image (const uint8_t * const image, size_t len)
{
    struct dos_header * dos_header = (struct dos_header *)image;
    uint32_t fixed_header_sz = 
        sizeof(struct optional_header_pe32plus) + sizeof(struct pe_header);

    //vmi_print_hex (image, MAX_HEADER_BYTES);

    if (IMAGE_DOS_HEADER != dos_header->signature) {
        dbprint ("--PEPARSE: DOS header signature not found\n");
        return VMI_FAILURE;
    }

    uint32_t ofs_to_pe = dos_header->offset_to_pe;

    if (ofs_to_pe > len - fixed_header_sz) {
        dbprint ("--PEPARSE: DOS header offset to PE value too big\n");
        return VMI_FAILURE;
    }

    struct pe_header * pe_header = (struct pe_header *) (image + ofs_to_pe);
    if (IMAGE_NT_SIGNATURE != pe_header->signature) {
        dbprint ("--PEPARSE: PE header signature invalid\n");
        return VMI_FAILURE;
    }

    // just get the magic # - we don't care here whether its PE or PE+
    struct optional_header_pe32 * pe_opt_header = (struct optional_header_pe32 *)
        ((uint8_t*)pe_header + sizeof(struct pe_header));

    if (IMAGE_PE32_MAGIC      != pe_opt_header->magic &&
        IMAGE_PE32_PLUS_MAGIC != pe_opt_header->magic   ) {
        dbprint ("--PEPARSE: Optional header magic value unknown\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t get_export_table (vmi_instance_t vmi, struct export_table *et)
{
    // Note: this function assumes a "normal" PE where all the headers are in
    // the first page of the PE and the field DosHeader.OffsetToPE points to
    // an address in the first page.

    addr_t export_header_rva = 0;
    addr_t export_header_va = 0;
    size_t nbytes = 0;
    addr_t base_vaddr = vmi->os.windows_instance.ntoskrnl_va;

#define MAX_HEADER_BYTES 1024 // keep under 1 page
    uint8_t image[MAX_HEADER_BYTES];

    /* scoop up the headers in a single read */
    nbytes = vmi_read_va (vmi, base_vaddr, 0, image, MAX_HEADER_BYTES);
    if (MAX_HEADER_BYTES != nbytes) {
        dbprint("--PEPARSE: failed to read PE header\n");
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == validate_pe_image (image, MAX_HEADER_BYTES)) {
        dbprint("--PEPARSE: failed to validate PE header(s)\n");
        return VMI_FAILURE;
    }

    /* Get basic data from the headers */
    struct dos_header * dos_header = (struct dos_header *)image;
    struct pe_header * pe_header = (struct pe_header *) (image + dos_header->offset_to_pe);

    /* read ahead to the ext pe header signature */
    void * pv_optional_pe_header = (void *) ((uint8_t*)pe_header + sizeof(struct pe_header));

    uint16_t magic = *((uint16_t*)pv_optional_pe_header);
    dbprint("--PEParse: magic is 0x%x\n", magic);

    if (IMAGE_PE32_MAGIC == magic){
        struct optional_header_pe32 *oh = 
            (struct optional_header_pe32 *) pv_optional_pe_header;
        export_header_rva = (addr_t) oh->idd[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;
    }
    else { // must be IMAGE_PE32_PLUS_MAGIC -- see validate_pe_image()
        struct optional_header_pe32plus *oh = 
            (struct optional_header_pe32plus *) pv_optional_pe_header;
        export_header_rva = (addr_t) oh->idd[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;
    }

    /* Find & read the export header; assume a different page than the headers */
    export_header_va = base_vaddr + export_header_rva;
    dbprint("--PEParse: found export table at [VA] 0x%.16llx = 0x%.16llx + 0x%x\n",
            export_header_va, vmi->os.windows_instance.ntoskrnl_va, export_header_rva );

    nbytes = vmi_read_va (vmi, export_header_va, 0, et, sizeof(*et));
    if (nbytes != sizeof(struct export_table)){
        dbprint("--PEParse: failed to map export header\n");
        return VMI_FAILURE;
    }

    /* sanity check */
    if (et->export_flags || !et->name){
        dbprint("--PEParse: bad export directory table\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

/* returns the rva value for a windows kernel export */
status_t windows_export_to_rva (vmi_instance_t vmi, char *symbol, addr_t *rva)
{
    struct export_table et;
    int aon_index = -1;
    int aof_index = -1;

    // get export table structure
    if (get_export_table(vmi, &et) != VMI_SUCCESS){
        dbprint("--PEParse: failed to get export table\n");
        return VMI_FAILURE;
    }

    // find AddressOfNames index for export symbol
    if ((aon_index = get_aon_index_binary (vmi, symbol, &et)) == -1) {
        dbprint("--PEParse: failed to get aon index\n");
        return VMI_FAILURE;
    }

    // find AddressOfFunctions index for export symbol
    if ((aof_index = get_aof_index(vmi, aon_index, &et)) == -1){
        dbprint("--PEParse: failed to get aof index\n");
        return VMI_FAILURE;
    }

    // find RVA value for export symbol
    return get_export_rva(vmi, rva, aof_index, &et);
}

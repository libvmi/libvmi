/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2009  Bryan D. Payne (bryan@thepaynes.cc)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * --------------------
 * This file contains functions that read information from a PE file
 * stored in a memory image.  Initially it is designed to extract 
 * exports from the kernel image, but may prove useful for more 
 * general applications later.
 *
 * File: windows_peparse.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 */

#include "xenaccess.h"
#include "xa_private.h"
#include <string.h>

#define IMAGE_DOS_HEADER 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT 12

struct image_data_directory{
    uint32_t virtual_address;
    uint32_t size;
};

struct file_header{
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
    // characteristics flags defined in pe.txt
};

struct optional_header{
    uint16_t magic;  // always 0x010b
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
};

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
};

struct export_table{
    uint32_t characteristics;
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
};

// takes an rva and looks up a null terminated string at that location
char *rva_to_string (xa_instance_t *instance, uint32_t rva)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    int length = 0;
    int max_length = 0;
    char *str = NULL;

    memory = xa_access_pa(
        instance,
        instance->os.windows_instance.ntoskrnl + rva,
        &offset,
        PROT_READ);
    if (NULL == memory){
        return NULL;
    }

    /* assuming that this is null terminated */
    max_length = instance->page_size - offset - 1;
    length = strnlen(memory + offset, max_length);
    if (length > 0){
        str = malloc(length + 1);
        memset(str, 0, length + 1);
        memcpy(str, memory + offset, length);
    }
    munmap(memory, instance->page_size);

    /* someone else will need to free this */
    return str;
}

void dump_exports (xa_instance_t *instance, struct export_table et)
{
    uint32_t base_addr = instance->os.windows_instance.ntoskrnl;
    unsigned char *memory1 = NULL;
    unsigned char *memory2 = NULL;
    unsigned char *memory3 = NULL;
    uint32_t offset1 = 0;
    uint32_t offset2 = 0;
    uint32_t offset3 = 0;
    uint32_t i = 0;
    uint32_t j = 0;

    /* load name list */    
    memory1 = xa_access_pa(
        instance,
        base_addr + et.address_of_names,
        &offset1,
        PROT_READ);

    /* load name ordinals list */
    memory2 = xa_access_pa(
        instance,
        base_addr + et.address_of_name_ordinals,
        &offset2,
        PROT_READ);

    /* load function locations */
    memory3 = xa_access_pa(
        instance,
        base_addr + et.address_of_functions,
        &offset3,
        PROT_READ);

    /* print names */
    for ( ; i < et.number_of_names; ++i){
        uint32_t rva = 0;
        uint16_t ordinal = 0;
        uint32_t loc = 0;
        char *str = NULL;
        memcpy(&rva, memory1+offset1+ i * sizeof(uint32_t), sizeof(uint32_t));
        if (rva){
            str = rva_to_string(instance, rva);
            if (str){
                memcpy(
                    &ordinal,
                    memory2 + offset2 + i * sizeof(uint16_t),
                    sizeof(uint16_t)
                );
                memcpy(
                    &loc,
                    memory3 + offset3 + ordinal * sizeof(uint32_t),
                    sizeof(uint32_t)
                );
                printf("%s:%d:0x%x\n", str, ordinal, loc);
                free(str);
            }
        }
    }
    /*TODO this loop is running past the end of memory page */

    munmap(memory1, instance->page_size);
    munmap(memory2, instance->page_size);
    munmap(memory3, instance->page_size);
}

int get_export_rva (
        xa_instance_t *instance, uint32_t *rva,
        int aof_index, struct export_table *et)
{
    uint32_t base_addr = instance->os.windows_instance.ntoskrnl;
    uint32_t rva_loc =
        base_addr + et->address_of_functions + aof_index * sizeof(uint32_t);

    return xa_read_long_phys(instance, rva_loc, rva);
}

int get_aof_index (
        xa_instance_t *instance, int aon_index, struct export_table *et)
{
    uint32_t base_addr = instance->os.windows_instance.ntoskrnl;
    uint32_t aof_index_loc =
        base_addr + et->address_of_name_ordinals + aon_index * sizeof(uint16_t);
    uint32_t aof_index = 0;

    if (xa_read_long_phys(instance, aof_index_loc, &aof_index) == XA_SUCCESS){
        return (int) (aof_index & 0xffff);
    }
    else{
        return -1;
    }
}

int get_aon_index (
        xa_instance_t *instance, char *symbol, struct export_table *et)
{
    /*TODO implement faster name search alg since names are sorted */
    uint32_t base_addr = instance->os.windows_instance.ntoskrnl;
    uint32_t i = 0;
    unsigned char *memory = NULL;
    uint32_t offset = 0;

    for ( ; i < et->number_of_names; ++i){
        uint32_t str_rva_loc =
            base_addr + et->address_of_names + i * sizeof(uint32_t);
        uint32_t str_rva = 0;
        xa_read_long_phys(instance, str_rva_loc, &str_rva);
        if (str_rva){
            char *rva = rva_to_string(instance, str_rva);
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

int get_export_table (xa_instance_t *instance, uint32_t base_addr, struct export_table *et)
{
    uint32_t value = 0;
    uint32_t signature_location = 0;
    uint32_t optional_header_location = 0;
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    struct optional_header oh;
    uint32_t export_header_rva = 0;

    /* signature location */
    xa_read_long_phys(instance, base_addr + 60, &value);
    signature_location = base_addr + value;

    /* optional header */
    optional_header_location = signature_location+4+sizeof(struct file_header);
    memory = xa_access_pa(
        instance,
        optional_header_location,
        &offset,
        PROT_READ);
    if (NULL == memory){
        return XA_FAILURE;
    }
    memcpy(&oh, memory + offset, sizeof(struct optional_header));
    munmap(memory, instance->page_size);
    export_header_rva = oh.idd[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;

    /* export header */
    memory = xa_access_pa(
        instance,
        base_addr + export_header_rva,
        &offset,
        PROT_READ);
    if (NULL == memory){
        return XA_FAILURE;
    }
    memcpy(et, memory + offset, sizeof(struct export_table));
    munmap(memory, instance->page_size);

    return XA_SUCCESS;
}

/* returns the rva value for a windows kernel export */
int windows_export_to_rva (xa_instance_t *instance, char *symbol, uint32_t *rva)
{
    uint32_t base_addr = instance->os.windows_instance.ntoskrnl;
    struct export_table et;
    int aon_index = -1;
    int aof_index = -1;

    // get export table structure
    if (get_export_table(instance, base_addr, &et) != XA_SUCCESS){
        return XA_FAILURE;
    }

    // find AddressOfNames index for export symbol
    if ((aon_index = get_aon_index(instance, symbol, &et)) == -1){
        return XA_FAILURE;
    }

    // find AddressOfFunctions index for export symbol
    if ((aof_index = get_aof_index(instance, aon_index, &et)) == -1){
        return XA_FAILURE;
    }

    // find RVA value for export symbol
    return get_export_rva(instance, rva, aof_index, &et);
}

int valid_ntoskrnl_start (xa_instance_t *instance, uint32_t addr)
{
    uint32_t value = 0;
    uint32_t signature_location = 0;
    struct export_table et;
    char *name = NULL;
    int ret = XA_FAILURE;

    xa_dbprint("--PEParse: checking possible ntoskrnl start at 0x%.8x\n", addr);

    /* validate DOS header */
    xa_read_long_phys(instance, addr, &value);
    if ((value & 0xffff) != IMAGE_DOS_HEADER){
        xa_dbprint("--PEParse: bad header, no IMAGE_DOS_HEADER\n");
        return XA_FAILURE;
    }

    /* validate nt signature */
    xa_read_long_phys(instance, addr + 60, &value);
    signature_location = addr + value;
    xa_read_long_phys(instance, signature_location, &value);
    if (value != IMAGE_NT_SIGNATURE){
        xa_dbprint("--PEParse: bad header, no IMAGE_NT_SIGNATURE\n");
        return XA_FAILURE;
    }

    /* check name via export table */
    if (get_export_table(instance, addr, &et) != XA_SUCCESS){
        return XA_FAILURE;
    }
    name = rva_to_string(instance, et.name + addr);
    if (NULL != name){
        if (strcmp(name, "ntoskrnl.exe") == 0){
            ret = XA_SUCCESS;
        }
        else{
            xa_dbprint("--PEParse: bad name (%s) at 0x%x\n", name, et.name);
        }
        free(name);
    }

    return ret;
}

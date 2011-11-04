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
};

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
};

// takes an rva and looks up a null terminated string at that location
char *rva_to_string (vmi_instance_t vmi, addr_t rva)
{
    addr_t paddr = vmi->os.windows_instance.ntoskrnl + rva;
    return vmi_read_str_pa(vmi, paddr);
}

void dump_exports (vmi_instance_t vmi, struct export_table et)
{
    uint32_t base_addr = vmi->os.windows_instance.ntoskrnl;
    addr_t base1 = base_addr + et.address_of_names;
    addr_t base2 = base_addr + et.address_of_name_ordinals;
    addr_t base3 = base_addr + et.address_of_functions;
    uint32_t i = 0;

    /* print names */
    for ( ; i < et.number_of_names; ++i){
        uint32_t rva = 0;
        uint16_t ordinal = 0;
        uint32_t loc = 0;
        char *str = NULL;
        vmi_read_32_pa(vmi, base1 + i * sizeof(uint32_t), &rva);
        if (rva){
            str = rva_to_string(vmi, (addr_t) rva);
            if (str){
                vmi_read_16_pa(vmi, base2 + i * sizeof(uint16_t), &ordinal);
                vmi_read_32_pa(vmi, base3 + ordinal + sizeof(uint32_t), &loc);
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
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl;
    addr_t rva_loc =
        base_addr + et->address_of_functions + aof_index * sizeof(uint32_t);

    uint32_t tmp = 0;
    status_t ret = vmi_read_32_pa(vmi, rva_loc, &tmp);
    *rva = (addr_t) tmp;
    return ret;
}

int get_aof_index (
        vmi_instance_t vmi, int aon_index, struct export_table *et)
{
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl;
    addr_t aof_index_loc =
        base_addr + et->address_of_name_ordinals + aon_index * sizeof(uint16_t);
    uint32_t aof_index = 0;

    if (vmi_read_32_pa(vmi, aof_index_loc, &aof_index) == VMI_SUCCESS){
        return (int) (aof_index & 0xffff);
    }
    else{
        return -1;
    }
}

int get_aon_index (
        vmi_instance_t vmi, char *symbol, struct export_table *et)
{
    /*TODO implement faster name search alg since names are sorted */
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl;
    uint32_t i = 0;
    unsigned char *memory = NULL;
    uint32_t offset = 0;

    for ( ; i < et->number_of_names; ++i){
        addr_t str_rva_loc =
            base_addr + et->address_of_names + i * sizeof(uint32_t);
        uint32_t str_rva = 0;
        vmi_read_32_pa(vmi, str_rva_loc, &str_rva);
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

status_t get_export_table (vmi_instance_t vmi, addr_t base_addr, struct export_table *et)
{
    uint32_t value = 0;
    addr_t signature_location = 0;
    addr_t optional_header_location = 0;
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    addr_t export_header_rva = 0;
    size_t nbytes = 0;

    /* signature location */
    vmi_read_32_pa(vmi, base_addr + 0x3c, &value);
    signature_location = base_addr + value;

    /* optional header */
    optional_header_location = signature_location + 4 + sizeof(struct file_header);
    
    /* check magic value */
    uint16_t magic = 0;
    vmi_read_16_pa(vmi, optional_header_location, &magic);
    dbprint("--PEParse: magic is 0x%x\n", magic);

    if (0x10b == magic){
        struct optional_header_pe32 oh;
        nbytes = vmi_read_pa(
            vmi,
            optional_header_location,
            &oh,
            sizeof(struct optional_header_pe32));
        if (nbytes != sizeof(struct optional_header_pe32)){
            dbprint("--PEParse: failed to map optional header\n");
            return VMI_FAILURE;
        }
        export_header_rva = (addr_t) oh.idd[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;
    }
    else if (0x20b == magic){
        struct optional_header_pe32plus oh;
        nbytes = vmi_read_pa(
            vmi,
            optional_header_location,
            &oh,
            sizeof(struct optional_header_pe32plus));
        if (nbytes != sizeof(struct optional_header_pe32plus)){
            dbprint("--PEParse: failed to map optional header\n");
            return VMI_FAILURE;
        }
        export_header_rva = (addr_t) oh.idd[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;
    }
    else{
        dbprint("--PEParse: invalid magic value for optional header\n");
        return VMI_FAILURE;
    }

    /* export header */
    dbprint("--PEParse: export_header_rva = 0x%llx\n", export_header_rva);
    nbytes = vmi_read_pa(
        vmi,
        base_addr + export_header_rva,
        et,
        sizeof(struct export_table));
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
    addr_t base_addr = vmi->os.windows_instance.ntoskrnl;
    struct export_table et;
    int aon_index = -1;
    int aof_index = -1;

    // get export table structure
    if (get_export_table(vmi, base_addr, &et) != VMI_SUCCESS){
        dbprint("--PEParse: failed to get export table\n");
        return VMI_FAILURE;
    }

    // find AddressOfNames index for export symbol
    if ((aon_index = get_aon_index(vmi, symbol, &et)) == -1){
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

status_t valid_ntoskrnl_start (vmi_instance_t vmi, addr_t addr)
{
    uint32_t value = 0;
    addr_t signature_location = 0;
    struct export_table et;
    char *name = NULL;
    int ret = VMI_FAILURE;

    dbprint("--PEParse: checking possible ntoskrnl start at 0x%llx\n", addr);

    /* validate DOS header */
    vmi_read_32_pa(vmi, addr, &value);
    if ((value & 0xffff) != IMAGE_DOS_HEADER){
        dbprint("--PEParse: bad header, no IMAGE_DOS_HEADER\n");
        return VMI_FAILURE;
    }

    unsigned char buf[0x50];
    vmi_read_pa(vmi, addr, buf, 0x50);
    vmi_print_hex(buf, 0x50);

    /* validate nt signature */
    vmi_read_32_pa(vmi, addr + 0x3c, &value);
    signature_location = addr + value;
    vmi_read_32_pa(vmi, signature_location, &value);
    if (value != IMAGE_NT_SIGNATURE){
        dbprint("--PEParse: bad header, no IMAGE_NT_SIGNATURE\n");
        return VMI_FAILURE;
    }

    /* check name via export table */
    if (get_export_table(vmi, addr, &et) != VMI_SUCCESS){
        return VMI_FAILURE;
    }

    vmi_print_hex(&et, sizeof(struct export_table));
    // next line assumes that ntoskrnl in vmi_instance is zero

    name = rva_to_string(vmi, (addr_t) et.name + addr);
    if (NULL != name){
        if (strcmp(name, "ntoskrnl.exe") == 0){
            dbprint("--PEParse: found it (%s) at 0x%x\n", name, et.name);
            ret = VMI_SUCCESS;
        }
        else{
            dbprint("--PEParse: bad name (%s) at 0x%x\n", name, et.name);
        }
        free(name);
    }

    return ret;
}

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

#ifndef LIBVMI_PEPARSE_H
#define LIBVMI_PEPARSE_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

#define IMAGE_DOS_HEADER 0x5A4D // ZM
#define IMAGE_NT_SIGNATURE 0x00004550   // 00EP

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

struct image_data_directory {
    uint32_t virtual_address;
    uint32_t size;
} __attribute__ ((packed));

struct pe_header {
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
    uint8_t reserved[32];
    uint32_t offset_to_pe;
} __attribute__ ((packed));

struct optional_header_pe32 {
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

struct optional_header_pe32plus {
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

struct section_header {
    char short_name[8];
    union {
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

struct export_table {
    uint32_t export_flags;  // reserved, must be 0
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name;
    uint32_t base;
    uint32_t number_of_functions;   // total number of exported items
    uint32_t number_of_names;
    uint32_t address_of_functions;
    uint32_t address_of_names;
    uint32_t address_of_name_ordinals;
} __attribute__ ((packed));

/**
 * Validate a PE image by checking for the DOS header, NT signature,
 * and the optional header type.
 *
 * @param[in] image, the image to be validated
 * @param[in] len, length of the image
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t
peparse_validate_pe_image(
    const uint8_t * const image,
    size_t len);

/**
 * Return a valid PE image if one was found
 * at the provided context.
 *
 * @param[in] vmi, the vmi instance
 * @param[in] ctx, Access context to get image from
 * @param[in] len, length to read
 * @param[out] image, address to store the data at
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t
peparse_get_image(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t len,
    const uint8_t * const image);

/**
 * Assign PE headers to an image.
 *
 * @param[in] image, the image to be validated
 * @param[out] dos_header, (Optional) Pointer to store the dos_header at
 * @param[out] pe_header,(Optional) Pointer to store the pe_header at
 * @param[out] optional_header_type, (Optional) Pointer to store the optional header type at
 * @param[out] optional_pe_header, (Optional) Pointer to store an unclassified optional header
 * @param[out] oh_pe32, (Optional) Pointer to store the PE32 type optional header
 * @param[out] oh_pe32plus, (Optional), Pointer to store the PE32_PLUS type optional header
 */
void
peparse_assign_headers(
    const uint8_t * const image,
    struct dos_header **dos_header,
    struct pe_header **pe_header,
    uint16_t *optional_header_type,
    void **optional_pe_header,
    struct optional_header_pe32 **oh_pe32,
    struct optional_header_pe32plus **oh_pe32plus);

/**
 * Get an RVA value from the PE image data directory (idd).
 * This function can take either the optional_header_type and the
 * unclassified optional_header
 * or one of the oh_pe32 and oh_pe32plus pointers as input.
 *
 * @param[in] entry_id, Image directory entry ID to get
 * @param[in] optional_header_type, (Optional, requires optional_header) Type of the optional header
 * @param[in] optional_header, (Optional, requires optional_header_type) Unclassified pointer to the optional header
 * @param[in] oh_pe32, (Optional) PE32 type pointer to the optional header
 * @param[in] oh_pe32plus, (Optional) PE32_PLUS type pointer to the optional header
 */
addr_t
peparse_get_idd_rva(
    uint32_t entry_id,
    uint16_t *optional_header_type,
    void *optional_header,
    struct optional_header_pe32 *oh_pe32,
    struct optional_header_pe32plus *oh_pe32plus);

/**
 * Get the size from the PE image data directory (idd).
 * This function can take either the optional_header_type and the
 * unclassified optional_header
 * or one of the oh_pe32 and oh_pe32plus pointers as input.
 *
 * @param[in] entry_id, Image directory entry ID to get
 * @param[in] optional_header_type, (Optional, requires optional_header) Type of the optional header
 * @param[in] optional_header, (Optional, requires optional_header_type) Unclassified pointer to the optional header
 * @param[in] oh_pe32, (Optional) PE32 type pointer to the optional header
 * @param[in] oh_pe32plus, (Optional) PE32_PLUS type pointer to the optional header
 */
size_t
peparse_get_idd_size(
    uint32_t entry_id,
    uint16_t *optional_header_type,
    void *optional_header,
    struct optional_header_pe32 *oh_pe32,
    struct optional_header_pe32plus *oh_pe32plus);

/**
 * Get the export table from a PE image.
 *
 * @param[in] vmi, the libvmi instance
 * @param[in] ctx, Access context for the PE image base
 * @param[out] et, the address of the export_table to save data into
 * @param[out] (optional) export_table_rva, the rva of the export table as given in the IDD
 * @param[out] (optional) export_table_size, the size of the export table as given in the IDD
 */
status_t
peparse_get_export_table(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    struct export_table *et,
    addr_t *export_table_rva,
    size_t *export_table_size);

#pragma GCC visibility pop
#ifdef __cplusplus
}
#endif

#endif /* LIBVMI_PEPARSE_H */


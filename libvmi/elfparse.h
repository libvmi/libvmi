/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Thomas Dangl (thomas.dangl@posteo.de)
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

#ifndef LIBVMI_ELFPARSE_H
#define LIBVMI_ELFPARSE_H

#ifdef __cplusplus
extern "C" {
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#pragma GCC visibility push(default)

#define EI_NIDENT 16

#define ET_EXEC 2
#define ET_DYN 3

#define PT_DYNAMIC 2

#define DT_NULL 0
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_GNU_HASH 0x6ffffef5

struct elf64_ehdr {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__ ((packed));

struct elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__ ((packed));

struct elf64_sym {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} __attribute__ ((packed));

struct elf64_dyn {
    int64_t d_tag;
    uint64_t d_val;
} __attribute__ ((packed));

/**
 * Validate a ELF image by checking for the ELF magic,
 * file type, and program header table size.
 *
 * @param[in] image, the image to be validated
 * @param[in] len, length of the image
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t
elfparse_validate_elf_image(
    const uint8_t * const image,
    size_t len) NOEXCEPT;

/**
 * Return a valid ELF image if one was found
 * at the provided context.
 *
 * @param[in] vmi, the vmi instance
 * @param[in] ctx, Access context to get image from
 * @param[in] len, length to read
 * @param[out] image, address to store the data at
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t
elfparse_get_image(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t len,
    uint8_t * image) NOEXCEPT;

/**
 * Assign addresses of dynamic entry tables to an image.
 *
 * @param[in] image, the image from which to extract the tables
 * @param[out] hash, (Optional) Pointer to store the address of the hash table at
 * @param[out] gnu_hash, (Optional) Pointer to store the address of the GNU hash table at
 * @param[out] str, (Optional) Pointer to store the address of the string table at
 * @param[out] sym, (Optional) Pointer to store the address of the symbol table at
 */
void
elfparse_assign_tables(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    const uint8_t * const image,
    addr_t *hash,
    addr_t *gnu_hash,
    addr_t *str,
    addr_t *sym) NOEXCEPT;

#pragma GCC visibility pop
#ifdef __cplusplus
}
#endif

#endif /* LIBVMI_ELFPARSE_H */

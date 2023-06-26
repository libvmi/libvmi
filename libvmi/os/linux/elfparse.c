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

#include "private.h"
#include "elfparse.h"

#define ELFPARSE_MAX_PHNUM   32
#define ELFPARSE_MAX_DTAG    128
#define ELFPARSE_MAX_BUCKETS 4096
#define ELFPARSE_MAX_BLOOM   1024

status_t
elfparse_validate_elf_image(
    uint8_t *image,
    size_t len)
{
    struct elf64_ehdr *elf = (struct elf64_ehdr *) image;

    if (elf->e_ident[0] != 0x7F || elf->e_ident[1] != 'E'
            || elf->e_ident[2] != 'L' || elf->e_ident[3] != 'F') {
        dbprint(VMI_DEBUG_ELFPARSE, "--ELFPARSE: ELF header signature not found\n");
        return VMI_FAILURE;
    }

    if (elf->e_phoff + sizeof(struct elf64_phdr) * elf->e_phnum > len) {
        dbprint(VMI_DEBUG_ELFPARSE, "--ELFPARSE: program headers outside buffer\n");
        return VMI_FAILURE;
    }

    if (elf->e_type != ET_EXEC && elf->e_type != ET_DYN) {
        dbprint(VMI_DEBUG_ELFPARSE, "--ELFPARSE: unsupported file type\n");
        return VMI_FAILURE;
    }

    if (elf->e_phentsize != sizeof(struct elf64_phdr)) {
        dbprint(VMI_DEBUG_ELFPARSE, "--ELFPARSE: invalid program header size\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t
elfparse_get_image(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t len,
    uint8_t *image)
{
    if (VMI_FAILURE == vmi_read(vmi, ctx, len, (void *) image, NULL)) {
        dbprint(VMI_DEBUG_ELFPARSE, "--ELFPARSE: failed to read ELF header\n");
        return VMI_FAILURE;
    }

    if (VMI_SUCCESS != elfparse_validate_elf_image(image, len)) {
        dbprint(VMI_DEBUG_ELFPARSE, "--ELFPARSE: failed to validate ELF header\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

void
elfparse_assign_tables(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint8_t *image,
    addr_t *hash,
    addr_t *gnu_hash,
    addr_t *str,
    addr_t *sym)
{
    struct elf64_ehdr *elf = (struct elf64_ehdr *) image;
    struct elf64_phdr ph[ELFPARSE_MAX_PHNUM];
    struct elf64_phdr *h = ph;
    struct elf64_dyn d = { .d_tag = ~0 };
    access_context_t _ctx = *ctx;
    size_t phnum = MIN(elf->e_phnum, ELFPARSE_MAX_PHNUM), i;

    _ctx.addr += elf->e_phoff;
    if (VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(struct elf64_phdr) * phnum, ph, NULL))
        return;

    /* assumption: there is exactly one PT_DYNAMIC header. */
    for (; h < ph + phnum; h++) {
        if (h->p_type == PT_DYNAMIC)
            break;
    }

    if (h->p_type != PT_DYNAMIC)
        return;

    for (_ctx.addr = ctx->addr + h->p_vaddr, i = 0;
            d.d_tag != DT_NULL && i < ELFPARSE_MAX_DTAG;
            _ctx.addr += sizeof(struct elf64_dyn), i++) {
        if (VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(struct elf64_dyn), &d, NULL))
            break;

        switch (d.d_tag) {
            case DT_HASH:
                if (hash)
                    *hash = d.d_val;
                break;
            case DT_GNU_HASH:
                if (gnu_hash)
                    *gnu_hash = d.d_val;
                break;
            case DT_STRTAB:
                if (str)
                    *str = d.d_val;
                break;
            case DT_SYMTAB:
                if (sym)
                    *sym = d.d_val;
                break;
            default:
                break;
        }
    }
}

static inline uint32_t gnu_hash(const uint8_t* name)
{
    uint32_t h = 5381;

    for (; *name; name++)
        h = (h << 5) + h + *name;

    return h;
}

static status_t gnu_hash_lookup(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t str_tab,
    addr_t sym_tab,
    addr_t hash_tab,
    const char *name,
    addr_t *rva)
{
    access_context_t _ctx = *ctx, __ctx = _ctx;
    uint32_t hash = gnu_hash((uint8_t*) name);
    uint32_t table[4];

    _ctx.addr = hash_tab;
    if (VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(table), table, NULL))
        return VMI_FAILURE;

    uint64_t bloom[ELFPARSE_MAX_BLOOM];
    size_t bloom_size = MIN(table[2], ELFPARSE_MAX_BLOOM);
    _ctx.addr += sizeof(table);
    if (VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(uint64_t) * bloom_size, bloom, NULL))
        return VMI_FAILURE;

    uint64_t word = bloom[(hash / 64) % bloom_size];
    uint64_t mask = (1ull << (hash % 64)) | (1ull << ((hash >> table[3]) % 64));

    /* early bailout. */
    if ((word & mask) != mask)
        return VMI_SUCCESS;

    uint32_t buckets[ELFPARSE_MAX_BUCKETS];
    size_t buckets_size = MIN(table[0], ELFPARSE_MAX_BUCKETS);
    _ctx.addr += sizeof(uint64_t) * table[2];
    if (VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(uint32_t) * buckets_size, buckets, NULL))
        return VMI_FAILURE;

    uint32_t symix = buckets[hash % buckets_size];
    if (symix < table[1])
        return VMI_FAILURE;

    for (_ctx.addr += sizeof(uint32_t) * (table[0] + symix - table[1]);;
            symix++, _ctx.addr += sizeof(uint32_t)) {
        uint32_t chain;
        if (VMI_FAILURE == vmi_read_32(vmi, &_ctx, &chain))
            break;

        if ((hash & ~0b1) == (chain & ~0b1)) {
            struct elf64_sym sym;
            __ctx.addr = sym_tab + sizeof(struct elf64_sym) * symix;
            if (VMI_FAILURE == vmi_read(vmi, &__ctx, sizeof(struct elf64_sym), &sym, NULL))
                break;

            /*
             * technically we can still have hash collisions here,
             * so we cross-check our result with the string table.
             */
            __ctx.addr = str_tab + sym.st_name;
            char *n = vmi_read_str(vmi, &__ctx);
            if (!n)
                continue;

            if (strcmp(name, n) != 0) {
                free(n);
                continue;
            }

            free(n);
            *rva = sym.st_value;
            return VMI_SUCCESS;
        }

        if (chain & 0b1)
            break;
    }

    return VMI_FAILURE;
}

static uint32_t gnu_hash_max_symbols(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t hash_tab,
    uint32_t *max_symbols)
{
    access_context_t _ctx = *ctx;
    uint32_t table[4];

    _ctx.addr = hash_tab;
    if (VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(table), table, NULL))
        return VMI_FAILURE;

    uint32_t buckets[ELFPARSE_MAX_BUCKETS];
    _ctx.addr += sizeof(table) + sizeof(uint64_t) * table[2];
    if (VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(uint32_t) * MIN(table[0],
                                ELFPARSE_MAX_BUCKETS), buckets, NULL))
        return VMI_FAILURE;

    uint32_t last = 0;
    for (uint32_t i = 0; i < MIN(table[0], ELFPARSE_MAX_BUCKETS); i++)
        if (buckets[i] > last)
            last = buckets[i];

    for (;; last++) {
        uint32_t chain;
        _ctx.addr = hash_tab + sizeof(table) + sizeof(uint64_t) * table[2]
                    + sizeof(uint32_t) * (table[0] + last - table[1]);
        if (VMI_FAILURE == vmi_read_32(vmi, &_ctx, &chain))
            return VMI_FAILURE;

        if (chain & 0b1)
            break;
    }

    *max_symbols = last;
    return VMI_SUCCESS;
}

static inline uint32_t elf_hash(const uint8_t* name)
{
    uint32_t h = 0, g;

    for (; *name; name++) {
        h = (h << 4) + *name;
        if ((g = h & 0xf0000000))
            h ^= g >> 24;
        h &= ~g;
    }

    return h;
}

static status_t elf_hash_lookup(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t str_tab,
    addr_t sym_tab,
    addr_t hash_tab,
    const char *name,
    addr_t *rva)
{
    access_context_t _ctx = *ctx;
    uint32_t hash = elf_hash((uint8_t*) name);
    uint32_t table[2];

    _ctx.addr = hash_tab;
    if (VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(table), table, NULL))
        return VMI_FAILURE;

    uint32_t current;
    _ctx.addr += sizeof(table) + sizeof(uint32_t) * (hash % table[0]);
    if (VMI_FAILURE == vmi_read_32(vmi, &_ctx, &current))
        return VMI_FAILURE;

    while (current) {
        struct elf64_sym sym;
        _ctx.addr = sym_tab + sizeof(struct elf64_sym) * current;
        if (VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(struct elf64_sym), &sym, NULL))
            break;

        _ctx.addr = str_tab + sym.st_name;
        char *n = vmi_read_str(vmi, &_ctx);
        if (n && !strcmp(name, n)) {
            free(n);
            *rva = sym.st_value;
            return VMI_SUCCESS;
        } else if (n)
            free(n);

        _ctx.addr = hash_tab + sizeof(table) + sizeof(uint32_t) * (table[0] + current);
        if (VMI_FAILURE == vmi_read_32(vmi, &_ctx, &current))
            break;
    }

    return VMI_FAILURE;
}

static uint32_t elf_hash_max_symbols(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t hash_tab,
    uint32_t *max_symbols)
{
    access_context_t _ctx = *ctx;
    uint32_t table[2];

    _ctx.addr = hash_tab;
    if (VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(table), table, NULL))
        return VMI_FAILURE;

    *max_symbols = table[1];
    return VMI_SUCCESS;
}

/* returns the rva value for a linux ELF dynamic symbol */
status_t
linux_export_to_rva(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    const char *symbol,
    addr_t *rva)
{
    addr_t hash = 0, gnu_hash = 0, str = 0, sym = 0;
    uint8_t image[1024] = { 0 };

    if (VMI_FAILURE == elfparse_get_image(vmi, ctx, sizeof(image), image))
        return VMI_FAILURE;

    elfparse_assign_tables(vmi, ctx, image, &hash, &gnu_hash, &str, &sym);

    if (!str || !sym || (!hash && !gnu_hash)) {
        dbprint(VMI_DEBUG_ELFPARSE, "--ELFParse: failed to locate dynamic tables\n");
        return VMI_FAILURE;
    }

    /* approach 1: attempt to resolve the symbol through DT_GNU_HASH. */
    if (gnu_hash)
        return gnu_hash_lookup(vmi, ctx, str, sym, gnu_hash, symbol, rva);

    /*
     * note that on modern systems, the fallback will fail.
     * most executables and shared libraries will still contain DT_HASH,
     * however, since the dynamic linker only uses DT_GNU_HASH, DT_HASH is never accessed.
     * hence, the corresponding page is not present in main memory.
     * thus, the fallback is only intended for legacy systems (2006 and earlier).
     */
    dbprint(VMI_DEBUG_ELFPARSE, "--ELFParse: falling back to DT_HASH resolving\n");

    /* approach 2: attempt to resolve the symbol through DT_HASH. */
    return elf_hash_lookup(vmi, ctx, str, sym, hash, symbol, rva);
}

/* returns a linux ELF dynamic symbol from an RVA */
char*
linux_rva_to_export(
    vmi_instance_t vmi,
    addr_t rva,
    const access_context_t *ctx)
{
    addr_t hash = 0, gnu_hash = 0, str = 0, sym = 0;
    uint8_t image[1024] = { 0 };
    uint32_t max_symbols = 0;
    access_context_t _ctx = *ctx;

    if (VMI_FAILURE == elfparse_get_image(vmi, ctx, sizeof(image), image))
        return NULL;

    elfparse_assign_tables(vmi, ctx, image, &hash, &gnu_hash, &str, &sym);

    if (!str || !sym || (!hash && !gnu_hash)) {
        dbprint(VMI_DEBUG_ELFPARSE, "--ELFParse: failed to locate dynamic tables\n");
        return NULL;
    }

    /* approach 1: attempt to determine maximum numbers of entries through DT_HASH. */
    if (!hash || VMI_FAILURE == elf_hash_max_symbols(vmi, ctx, hash, &max_symbols))
        /* approach 2: attempt to determine maximum numbers of entries through DT_GNU_HASH. */
        if (!gnu_hash || VMI_FAILURE == gnu_hash_max_symbols(vmi, ctx, hash, &max_symbols))
            return NULL;

    /* linear search for the symbol. */
    _ctx.addr = sym;
    for (uint32_t i = 0; i < max_symbols; i++, _ctx.addr += sizeof(struct elf64_sym)) {
        struct elf64_sym s;
        if (VMI_FAILURE == vmi_read(vmi, &_ctx, sizeof(struct elf64_sym), &s, NULL))
            break;

        if (s.st_value == rva) {
            _ctx.addr = str + s.st_name;
            return vmi_read_str(vmi, &_ctx);
        }
    }

    return NULL;
}

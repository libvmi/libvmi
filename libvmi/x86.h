/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
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

#ifndef LIBVMI_X86_H
#define LIBVMI_X86_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

#define PTRS_PER_PDPI 4
#define PTRS_PER_PAE_PTE 512
#define PTRS_PER_PAE_PGD 512

#define PTRS_PER_NOPAE_PTE 1024
#define PTRS_PER_NOPAE_PGD 1024

/*
 * If READ_WRITE bit is set, the page is read/write. Otherwise when
 * it is not set, the page is read-only. The WP bit in CR0
 * determines if this is only applied to userland, always giving
 * the kernel write access (the default) or both userland and the
 * kernel (see Intel Manuals 3A 2-20).
 */
#define READ_WRITE(entry)       VMI_GET_BIT(entry, 1)

/*
 * The USER_SUPERVISOR controls access to the page based on privilege
 * level. If the bit is set, then the page may be accessed by all; if the
 * bit is not set, however, only the supervisor can access it. For a page
 * directory entry, the user bit controls access to all the pages referenced
 * by the page directory entry. Therefore if you wish to make a page a user
 * page, you must set the user bit in the relevant page directory entry as
 * well as the page table entry.
 */
#define USER_SUPERVISOR(entry)  VMI_GET_BIT(entry, 2)

/*
 * The WRITE_THROUGH bit controls 'Write-Through' abilities of the page.
 * If the bit is set, write-through caching is enabled. If not, then
 * write-back is enabled instead.
 */
#define WRITE_THROUGH(entry)    VMI_GET_BIT(entry, 3)

/*
 * If the CACHE_DISABLED bit is set, the page will not be cached.
 * Otherwise, it will be.
 */
#define CACHE_DISABLED(entry)   VMI_GET_BIT(entry, 4)

/*
 * The ACCESSED bit is used to discover whether a page has been read
 * or written to. If it has, then the bit is set, otherwise, it is not.
 * Note that, this bit will not be cleared by the CPU, so that burden
 * falls on the OS (if it needs this bit at all).
 */
#define ACCESSED(entry)         VMI_GET_BIT(entry, 5)

/*
 * The PAGE_SIZE bit stores the page size for that specific entry.
 * If the bit is set, then pages are large pages. Otherwise, they are 4 KiB.
 */
#define PAGE_SIZE(entry)        VMI_GET_BIT(entry, 7)

/*
 * The GLOBAL_PAGE bit determines if the PT/PTE is used across address spaces,
 * to prevent frequently used pages from being flushed from the TLB cache.
 * Only valid if CR4.PGE is set, ignored otherwised.
 */
#define GLOBAL_PAGE(entry)      VMI_GET_BIT(entry, 8)

/*
 * Bits 9-11 are available bits for the OS to use as it sees fit
 */

/*
 * The names PROTOTYPE and TRANSITION are Windows specific.
 * See: "Using Every Part of the Buffalo in Windows Memory Analysis" by
 * Jesse D. Kornblum for details.
 */
#define PROTOTYPE(entry)        VMI_GET_BIT(entry, 10)
#define TRANSITION(entry)       VMI_GET_BIT(entry, 11)

/* If the ENTRY_PRESENT bit is set, the page is actually in
 * physical memory at the moment. For example, when a page is
 * swapped out, it is not in physical memory and therefore not 'Present'.
 * If a page is called, but not present, a page fault will occur,
 * and the OS should handle it. (See below.)
 */
#define ENTRY_PRESENT(transition_pages, entry) \
    (VMI_GET_BIT(entry, 0) \
        ? 1 : \
        ( \
            (transition_pages && \
                (TRANSITION(entry) && !(PROTOTYPE(entry))) \
            ) \
            ? 1 : 0 \
        ) \
    )

/*
 * NX (No eXecute) bit refers to the most significant bit (i.e. the 63th, or leftmost) of a 64-
 * bit Page Table Entry. If this bit is set to 0, then code can be executed from that particular page. If it’s set to 1, then the
 * page is assumed to only retain data, and code execution should be prevented.
 */
#define NX(entry)               VMI_GET_BIT(entry, 63)

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif /* LIBMVI_X86_H */

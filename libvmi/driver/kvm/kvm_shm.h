/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Guanglin Xu (guanglin@andrew.cmu.edu)
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
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

#ifndef KVM_SHM_H
#define KVM_SHM_H

/** Guest virtual-medial-physical address mapping enables
 *   Direct Guest Virtual Memory Access (DGVMA) to the
 *   shm-snapshot.
 *  While the m2p mapping will be established at process
 *   page table and so MMU will take care of it, we must
 *   maintain v2m mapping by ourself.
 *  We use 3 structures to establish and maintain the v2m
 *   mapping. The three, from top to bottom, are v2m table,
 *   v2m_chunk and m2p mapping clue chunk.
 */

/* m2p mapping clue chunk is used to mmap guest physical
 *  address to medial address (i.e. LibVMI virtual address),
 *  and will be deleted just after mmap() because munmap()
 *  can be done with v2m chunk.
 * In a m2p chunk, the mappings between m and p are consecutive.
 */
typedef struct m2p_mapping_clue_chunk_struct {
    void * medial_mapping_addr;
    addr_t paddr_begin;
    addr_t paddr_end;
    addr_t vaddr_begin;
    addr_t vaddr_end;
    struct m2p_mapping_clue_chunk_struct* next;
} m2p_mapping_clue_chunk, *m2p_mapping_clue_chunk_t;

/* v2m chunk is used to maintain the mapping of v and m.
 *  We search an medial address of a given virtual address
 *  in a collection of v2m chunk.
 * In a m2p chunk, the virtual address range are continuous.
 */
typedef struct v2m_chunk_struct {
    addr_t vaddr_begin;
    addr_t vaddr_end;
    void * medial_mapping_addr;
    m2p_mapping_clue_chunk_t m2p_chunks;
    struct v2m_chunk_struct* next;
} v2m_chunk, *v2m_chunk_t;

/*
 * v2m table binds a pid and a list of v2m chunks
 */
typedef struct v2m_table_struct {
    pid_t pid;
    v2m_chunk_t v2m_chunks;
    struct v2m_table_struct* next;
} v2m_table, *v2m_table_t;

#endif /* KVM_SHM_H */

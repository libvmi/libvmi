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

/**
* @file vbd_private.h
* @brief The functions and structures concerning virtual block devices reading
* and description are defined here.
*
*/

#ifndef VBD_PRIVATE_H
#define VBD_PRIVATE_H

#define SECTOR_SIZE      0x00000200

#ifdef HAVE_ZLIB

#define QCOW2_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)

typedef struct QCowHeader {
    uint32_t magic;
    uint32_t version;

    uint64_t backing_file_offset;
    uint32_t backing_file_size;

    uint32_t cluster_bits;
    uint64_t size; /* in bytes */
    uint32_t crypt_method;

    uint32_t l1_size;
    uint64_t l1_table_offset;

    uint64_t refcount_table_offset;
    uint32_t refcount_table_clusters;

    uint32_t nb_snapshots;
    uint64_t snapshots_offset;
} QCowHeader;

#define QCOW2_L1_ENTRY_L2_TABLE_OFFSET        0x00fffffffffffe00ULL
#define QCOW2_L2_ENTRY_CLUSTER_DESCRIPTOR     0x3fffffffffffffffULL

#define QCOW2_L2_ENTRY_CLUSTER_TYPE_FLAG      (1ULL << 62)

#define QCOW2_STANDARD_CLUSTER_CLUSTER_OFFSET 0x3ffffffffffffffeULL

#define QCOW2_COMPRESSED_SECTOR_SIZE 512U
#define QCOW2_COMPRESSED_SECTOR_MASK (QCOW2_COMPRESSED_SECTOR_SIZE - 1ULL)

// typedef union L1TableEntry
// {
//       uint64_t All;
//       struct
//       {
//             uint64_t reserved1 : 9;  // set to 0
//             uint64_t l2_offset : 47; // offset in image file
//             uint64_t reserved2 : 7;  // set to 0
//             uint64_t used      : 1;  // 0 for an L2 table that is unused or requires COW, 1 if its
//                                      // refcount is exactly one. This information is only accurate
//                                      // in the active L1 table.
//       } Fields;
// } L1TableEntry;

// typedef union L2TableEntry //for Standart Cluster
// {
//       uint64_t All;
//       struct
//       {
//             uint64_t zeros          :  1;
//             uint64_t reserved1      :  8;
//             uint64_t cluster_offset : 47; // Bits 9-55 of host cluster offset. Must be aligned to a
//                                           // cluster boundary. If the offset is 0 and bit 63 is clear,
//                                           // the cluster is unallocated. The offset may only be 0 with
//                                           // bit 63 set (indicating a host cluster offset of 0) when an
//                                           // external data file is used.
//             uint64_t reserved2      :  6;
//             uint64_t comressed      :  1; // 0 for standard clusters
//                                           // 1 for compressed clusters
//             uint64_t used           :  1; // 0 for clusters that are unused, compressed or require COW.
//                                           // 1 for standard clusters whose refcount is exactly one.
//                                           // This information is only accurate in L2 tables
//                                           // that are reachable from the active L1 table.
//                                           // With external data files, all guest clusters have an
//                                           // implicit refcount of 1 (because of the fixed host = guest
//                                           // mapping for guest cluster offsets), so this bit should be 1
//                                           // for all allocated clusters.
//       } Fields;

// } L2TableEntry;

typedef struct QCowFile {
    FILE*          fp;
    QCowHeader     header;
    unsigned int   cluster_size;
    uint64_t       l2_size;
    uint64_t       l2_bits;
    uint64_t       l2_entry_size;
    uint64_t*      l1_table;
    char     filename[0x1000];
    char     backing_file[0x1000];
} QCowFile;

static status_t vbd_qcow2_open(QCowFile *qcowfile, const char *filename);
static status_t vbd_qcow2_do_read(QCowFile *qcowfile, uint64_t offset, size_t num, unsigned char *buffer);
static int vbd_qcow2_read_chunk(QCowFile *qcowfile, uint64_t offset, uint64_t num, unsigned char *buffer);
static status_t vbd_qcow2_read_l2_table(QCowFile *qcowfile, uint64_t l2_offset, uint64_t *table);
#endif

#endif

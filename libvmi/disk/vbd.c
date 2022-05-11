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

#include "private.h"
#include "disk/vbd_private.h"

#ifdef HAVE_ZLIB
#include <zlib.h>

static status_t vbd_read_qcow2_disk_impl(const char* backend_path, uint64_t offset, uint64_t count, void *buffer);

static int vbd_qcow2_uncompress_cluster(unsigned char *dest, size_t dest_size, unsigned char *src, size_t src_size)
{
    int ret;
    z_stream strm;

    memset(&strm, 0, sizeof(strm));
    strm.avail_in = src_size;
    strm.next_in = (void *) src;
    strm.avail_out = dest_size;
    strm.next_out = dest;

    ret = inflateInit2(&strm, -12);
    if (ret != Z_OK) {
        return -EIO;
    }

    ret = inflate(&strm, Z_FINISH);
    if ((ret == Z_STREAM_END || ret == Z_BUF_ERROR) && strm.avail_out == 0) {
        ret = 0;
    } else {
        ret = -EIO;
    }

    inflateEnd(&strm);

    return ret;
}

/* Free L1 table and close file object */
static void vbd_qcow2_close(QCowFile *qcowfile)
{
    if (qcowfile->l1_table)
        free(qcowfile->l1_table);
    if (qcowfile->fp)
        fclose(qcowfile->fp);
}

/* Read and parse QCow2 file header. All fields are Big Endian.
 */
static status_t vbd_qcow2_read_header(FILE *f, QCowHeader *header)
{
    size_t bytes_read;

    bytes_read = fread(header, 1, sizeof(QCowHeader), f);
    if (bytes_read != sizeof(QCowHeader)) {
        errprint("VMI_ERROR: vbd_qcow2_read_header: failed to read disk image header\n");
        return VMI_FAILURE;
    }

    header->magic                   = be32toh(header->magic);
    header->version                 = be32toh(header->version);
    header->backing_file_offset     = be64toh(header->backing_file_offset);
    header->backing_file_size       = be32toh(header->backing_file_size);
    header->cluster_bits            = be32toh(header->cluster_bits);
    header->size                    = be64toh(header->size);
    header->crypt_method            = be32toh(header->crypt_method);
    header->l1_size                 = be32toh(header->l1_size);
    header->l1_table_offset         = be64toh(header->l1_table_offset);
    header->refcount_table_offset   = be64toh(header->refcount_table_offset);
    header->refcount_table_clusters = be32toh(header->refcount_table_clusters);
    header->nb_snapshots            = be32toh(header->nb_snapshots);
    header->snapshots_offset        = be64toh(header->snapshots_offset);

    if (header->magic != QCOW2_MAGIC) {
        errprint("VMI_ERROR: vbd_qcow2_read_header: bad disk image header magic\n");
        return VMI_FAILURE;
    }

    if ( header->version < 2 || header->version > 3 ) {
        errprint("VMI_ERROR: vbd_qcow2_read_header: unsupported QCow2 version\n");
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

static status_t vbd_qcow2_read_l1_table(QCowFile *qcowfile)
{
    uint64_t *tmp = malloc(qcowfile->header.l1_size * sizeof(uint64_t));
    if (!tmp) {
        errprint("VMI_ERROR: vbd_qcow2_read_header: failed to allocate tmp buffer for L1 table\n");
        return VMI_FAILURE;
    }
    memset(tmp, 0, (qcowfile->header.l1_size * sizeof(uint64_t)));

    fseek(qcowfile->fp, qcowfile->header.l1_table_offset, SEEK_SET);
    if (!fread(tmp, sizeof(uint64_t) * qcowfile->header.l1_size, 1, qcowfile->fp)) {
        errprint("VMI_ERROR: vbd_qcow2_read_header: failed to read entire L1 table\n");
        free(tmp);
        return VMI_FAILURE;
    }

    for (unsigned int i = 0; i < qcowfile->header.l1_size; i++) {
        qcowfile->l1_table[i] = be64toh(tmp[i]);
    }
    free(tmp);

    return VMI_SUCCESS;
}

/* Open QCow2 disk image, read header, L1 table, calculate cluster size, L2 table
 * entry size and number of entries.
 * https://github.com/qemu/qemu/blob/master/docs/interop/qcow2.txt
 * https://people.gnome.org/~markmc/qcow-image-format.html
 */
static status_t vbd_qcow2_open(QCowFile *qcowfile, const char *filename)
{
    strcpy(qcowfile->filename, filename);
    qcowfile->fp = fopen(filename, "rb");
    if (!qcowfile->fp) {
        errprint("VMI_ERROR: vbd_qcow2_open: failed to open qcow2 disk image file\n");
        return VMI_FAILURE;
    }

    memset(&qcowfile->header, 0, sizeof(QCowHeader));
    if (VMI_FAILURE == vbd_qcow2_read_header(qcowfile->fp, &qcowfile->header)) {
        errprint("VMI_ERROR: vbd_qcow2_open: failed to read qcow2 disk image header\n");
        fclose(qcowfile->fp);
        qcowfile->fp = NULL;
        return VMI_FAILURE;
    }

    /* Check wheter disk image has backing file */
    if (qcowfile->header.backing_file_offset) {
        if (qcowfile->header.backing_file_size > 0x1000) {
            errprint("VMI_ERROR: vbd_qcow2_open: backing file name size is too large");
            fclose(qcowfile->fp);
            qcowfile->fp = NULL;
            return VMI_FAILURE;
        }
        fseek(qcowfile->fp, qcowfile->header.backing_file_offset, SEEK_SET);
        char *backing_file_name = malloc(0x1000);
        memset(backing_file_name, 0, 0x1000);
        if (fread(backing_file_name, qcowfile->header.backing_file_size, 1, qcowfile->fp) == 0) {
            errprint("VMI_ERROR: vbd_qcow2_open: failed to read qcow2 backing image file name\n");
            free(backing_file_name);
            fclose(qcowfile->fp);
            qcowfile->fp = NULL;
            return VMI_FAILURE;
        }
        /* Check if backing file has absolute path then simply copy it to structure */
        if (!strncmp(backing_file_name, "/", 1)) {
            g_stpcpy(qcowfile->backing_file, backing_file_name);
        } else if (!strncmp(backing_file_name, "json:", 5)) {
            char prefix[] = "\"filename\": \"";
            char *p = strstr(backing_file_name, prefix);
            if (p) {
                p += sizeof(prefix) - 1;
                char *end = strchr(p, '"');
                strncpy(qcowfile->backing_file, p, end - p);
            }
        }
        /* If backing file has relative path, let's assume that it is located in the same directory as main file*/
        else {
            char* filename_pos = strrchr(qcowfile->filename, '/') + 1;
            if (filename_pos != NULL) {
                int path_len = (uint64_t)filename_pos - (uint64_t)qcowfile->filename;
                strncpy(qcowfile->backing_file, qcowfile->filename, path_len);
                if ((path_len + qcowfile->header.backing_file_size) > 0x1000) {
                    errprint("VMI_ERROR: vbd_qcow2_open: failed to reconstruct backing file path, resulting path is too large");
                    free(backing_file_name);
                    fclose(qcowfile->fp);
                    qcowfile->fp = NULL;
                    return VMI_FAILURE;
                }
                strncat(qcowfile->backing_file, backing_file_name, qcowfile->header.backing_file_size);
            } else {
                errprint("VMI_ERROR: vbd_qcow2_open: failed to reconstruct backing image file path\n");
                fclose(qcowfile->fp);
                qcowfile->fp = NULL;
                free(backing_file_name);
                return VMI_FAILURE;
            }

        }
        free(backing_file_name);
    }
    /* Calculate image cluster size. Most times cluster_bits is 0x10 */
    qcowfile->cluster_size = 1 << qcowfile->header.cluster_bits;
    if (!qcowfile->cluster_size) {
        errprint("VMI_ERROR: vbd_qcow2_open: disk image cluster size is zero\n");
        fclose(qcowfile->fp);
        qcowfile->fp = NULL;
        return VMI_FAILURE;
    }
    qcowfile->l2_entry_size = sizeof(uint64_t);

    qcowfile->l1_table = malloc(qcowfile->header.l1_size * sizeof(uint64_t));
    if (!qcowfile->l1_table) {
        errprint("VMI_ERROR: vbd_qcow2_open: failed to allocate memory for L1 table\n");
        fclose(qcowfile->fp);
        qcowfile->fp = NULL;
        return VMI_FAILURE;
    }
    memset(qcowfile->l1_table, 0, qcowfile->header.l1_size * sizeof(uint64_t));
    if (VMI_FAILURE == vbd_qcow2_read_l1_table(qcowfile)) {
        errprint("VMI_ERROR: vbd_qcow2_open: failed to read L1 table\n");
        free(qcowfile->l1_table);
        qcowfile->l1_table = NULL;
        fclose(qcowfile->fp);
        qcowfile->fp = NULL;
        return VMI_FAILURE;
    }


    qcowfile->l2_bits = qcowfile->header.cluster_bits - 3;
    qcowfile->l2_size = qcowfile->cluster_size / qcowfile->l2_entry_size;

    return VMI_SUCCESS;
}

/* Read L2 table and convert entries from Big Endian */
static status_t vbd_qcow2_read_l2_table(QCowFile *qcowfile, uint64_t l2_offset, uint64_t *table)
{
    uint64_t *tmp = malloc(qcowfile->cluster_size);
    if (!tmp) {
        errprint("VMI_ERROR: vbd_qcow2_read_l2_table: failed to allocate temp buffer  L2 table\n");
        return VMI_FAILURE;
    }
    memset(tmp, 0, qcowfile->cluster_size);
    fseek(qcowfile->fp, l2_offset, SEEK_SET);
    if (!fread(tmp, qcowfile->cluster_size, 1, qcowfile->fp)) {
        errprint("VMI_ERROR: vbd_qcow2_read_l2_table: failed to read L2 table\n");
        free(tmp);
        return VMI_FAILURE;
    }
    for (unsigned int i = 0; i < qcowfile->l2_size; i++) {
        table[i] = be64toh(tmp[i]);
    }
    free(tmp);

    return VMI_SUCCESS;
}

/* Read data from disk chunk by chunk. */
static status_t vbd_qcow2_do_read(QCowFile *qcowfile, uint64_t offset, size_t num, unsigned char *buffer)
{
    unsigned char *p_buf = buffer;
    uint64_t left = num;
    int bytes_read = 0;
    uint64_t curr_offset = offset;

    while (left > 0) {
        bytes_read = vbd_qcow2_read_chunk(qcowfile, curr_offset, left, p_buf);
        if ( bytes_read < 0 || (unsigned int)bytes_read > qcowfile->cluster_size) {
            return VMI_FAILURE;
        }
        p_buf += bytes_read;
        curr_offset += bytes_read;
        left -= bytes_read;
    }

    return VMI_SUCCESS;
}

/* Perform reading https://github.com/qemu/qemu/blob/9aef0954195cc592e86846dbbe7f3c2c5603690a/docs/interop/qcow2.txt#L506 */
static int vbd_qcow2_read_chunk(QCowFile *qcowfile, uint64_t offset, uint64_t num, unsigned char *buffer)
{
    unsigned int l1_idx, l2_idx, offset_in_cluster;
    uint64_t  cluster_offset;
    uint64_t  l2_offset;
    uint64_t* l2_table;
    uint64_t  l2_entry;

    unsigned int compressed = 0;
    unsigned int csize = 0;
    int uncompress_ret;

    /* https://github.com/qemu/qemu/blob/b22726abdfa54592d6ad88f65b0297c0e8b363e2/docs/interop/qcow2.txt#L512 */
    l1_idx = (offset / qcowfile->cluster_size) / (qcowfile->cluster_size / qcowfile->l2_entry_size);
    if (l1_idx > qcowfile->header.l1_size) {
        errprint("VMI_ERROR: vbd_qcow2_read_chunk: L1 index > L1 size\n");
        return -1;
    }
    l2_idx = (offset / qcowfile->cluster_size) % (qcowfile->cluster_size / qcowfile->l2_entry_size);
    if (l2_idx > qcowfile->l2_size) {
        errprint("VMI_ERROR: vbd_qcow2_read_chunk: L2 index > L2 size\n");
        return -1;
    }
    offset_in_cluster = offset % qcowfile->cluster_size;

    unsigned int num_bytes = qcowfile->cluster_size - offset_in_cluster;
    if ( num < num_bytes) {
        num_bytes = num;
    }

    l2_offset = qcowfile->l1_table[l1_idx] & QCOW2_L1_ENTRY_L2_TABLE_OFFSET;

    /* If L2 table offset is zero then target cluster is not allocated in current file.
     * Let's check backing file
     */
    if (l2_offset == 0) {
        if (!*qcowfile->backing_file) {
            errprint("VMI_ERROR: vbd_qcow2_read_chunk: backing file is empty\n");
            return -1;
        }
        if (VMI_FAILURE == vbd_read_qcow2_disk_impl(qcowfile->backing_file, offset, num, buffer)) {
            errprint("VMI_ERROR: vbd_qcow2_read_chunk: failed to access backing file\n");
            return -1;
        }
        return num_bytes;
    }

    l2_table = malloc(qcowfile->cluster_size);
    if (!l2_table) {
        errprint("VMI_ERROR: vbd_qcow2_read_chunk: failed to allocate memory for L2 table\n");
        return -1;
    }

    memset(l2_table, 0, qcowfile->cluster_size);
    if (VMI_FAILURE == vbd_qcow2_read_l2_table(qcowfile, l2_offset, l2_table)) {
        errprint("VMI_ERROR: vbd_qcow2_read_chunk: failed to read L2 table\n");
        free(l2_table);
        return -1;
    }

    l2_entry = l2_table[l2_idx];

    if (l2_entry & QCOW2_L2_ENTRY_CLUSTER_TYPE_FLAG) {
        unsigned int csize_mask;
        unsigned int csize_shift;
        unsigned int nb_csectors;

        compressed = 1;

        csize_mask = (1 << (qcowfile->header.cluster_bits - 8)) - 1;
        csize_shift = 62 - (qcowfile->header.cluster_bits - 8);

        cluster_offset = l2_entry & ((1ULL << csize_shift) - 1);

        nb_csectors = ((l2_entry >> csize_shift) & csize_mask) + 1;
        csize = nb_csectors * QCOW2_COMPRESSED_SECTOR_SIZE - (cluster_offset & QCOW2_COMPRESSED_SECTOR_MASK);
        if (csize <= 0) {
            errprint("VMI_ERROR: vbd_qcow2_read_chunk: compressed cluster size is negative or zero\n");
            free(l2_table);
            return -1;
        }
    } else {
        /* Standard cluster */
        uint64_t cluster_descriptor = l2_entry & QCOW2_L2_ENTRY_CLUSTER_DESCRIPTOR;
        cluster_offset = cluster_descriptor & QCOW2_STANDARD_CLUSTER_CLUSTER_OFFSET;
    }

    /* Similar as for L2 table. If cluster offset is zero then target cluster is not allocated in current file */
    if (cluster_offset == 0) {
        if (!*qcowfile->backing_file) {
            errprint("VMI_ERROR: vbd_qcow2_read_chunk: backing file is empty\n");
            free(l2_table);
            return -1;
        }
        if (VMI_FAILURE == vbd_read_qcow2_disk_impl(qcowfile->backing_file, offset, num, buffer)) {
            errprint("VMI_ERROR: vbd_qcow2_read_chunk: failed to access backing file\n");
            free(l2_table);
            return -1;
        }
        free(l2_table);
        return num_bytes;
    }



    if ((num_bytes + offset_in_cluster) > qcowfile->cluster_size) { // Number of bytes exceed size of cluster
        errprint("VMI_ERROR: vbd_qcow2_read_chunk: requested read len exceeds size of cluster\n");
        free(l2_table);
        return -1;
    }

    fseek(qcowfile->fp, cluster_offset, SEEK_SET);

    size_t cluster_len = compressed ? csize : qcowfile->cluster_size;
    unsigned char* cluster = malloc(cluster_len);
    if (!cluster) {
        errprint("VMI_ERROR: vbd_qcow2_read_chunk: failed to allocate cluster temp buffer\n");
        free(l2_table);
        return -1;
    }

    if (!fread(cluster, cluster_len, 1, qcowfile->fp)) {
        errprint("VMI_ERROR: vbd_qcow2_read_chunk: failed to read cluster\n");
        free(l2_table);
        free(cluster);
        return -1;
    }

    if (compressed) {
        unsigned char *uncompressed = malloc(qcowfile->cluster_size);
        if (!uncompressed) {
            errprint("VMI_ERROR: vbd_qcow2_read_chunk: failed to allocate buffer for uncompressed cluster\n");
            free(l2_table);
            free(cluster);
            return -1;
        }

        uncompress_ret = vbd_qcow2_uncompress_cluster(uncompressed, qcowfile->cluster_size, cluster, csize);

        if (!uncompress_ret) {
            memcpy(buffer, uncompressed + offset_in_cluster, num_bytes);
            free(uncompressed);
        } else {
            free(cluster);
            free(uncompressed);
            errprint("VMI_ERROR: vbd_qcow2_read_chunk: failed to uncompress cluster\n");
            free(l2_table);
            return -1;
        }
    } else {
        memcpy(buffer, cluster + offset_in_cluster, num_bytes);
    }

    free(cluster);
    free(l2_table);

    return num_bytes;
}

status_t vbd_read_qcow2_disk(vmi_instance_t UNUSED(vmi), const char* backend_path, uint64_t offset, uint64_t count, void *buffer)
{
    return vbd_read_qcow2_disk_impl(backend_path, offset, count, buffer);
}

static status_t vbd_read_qcow2_disk_impl(const char* backend_path, uint64_t offset, uint64_t count, void *buffer)
{
    QCowFile qcowfile;
    memset(&qcowfile, 0, sizeof(QCowFile));

    if (VMI_FAILURE == vbd_qcow2_open(&qcowfile, backend_path)) {
        errprint("VMI_ERROR: %s: failed to open disk image\n", __FUNCTION__);
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == vbd_qcow2_do_read(&qcowfile, offset, count, buffer)) {
        errprint("VMI_ERROR: %s: failed perform read operation\n", __FUNCTION__);
        vbd_qcow2_close(&qcowfile);
        return VMI_FAILURE;
    }
    vbd_qcow2_close(&qcowfile);

    return VMI_SUCCESS;
}
#endif

/*
 * Open and read physical (or logical) drive as file.
 */
status_t vbd_read_raw_disk(vmi_instance_t UNUSED(vmi), const char* backend_path, uint64_t offset, uint64_t count, void *buffer)
{
    FILE *f;
    size_t bytes_read;

    f = fopen(backend_path, "rb");
    if (!f) {
        errprint("VMI_ERROR: vbd_read_raw_disk: failed to open backend path\n");
        return VMI_FAILURE;
    }

    fseek(f, offset, SEEK_SET);
    bytes_read = fread(buffer, 1, count, f);
    if (bytes_read != count || bytes_read == 0) {
        errprint("VMI_ERROR: vbd_read_raw_disk: failed to open backend path\n");
        fclose(f);
        return VMI_FAILURE;
    }

    fclose(f);

    return VMI_SUCCESS;
}

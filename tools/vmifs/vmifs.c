/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel 2013 (tamas.lengyel@zentific.com)
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

#include <config.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <libvmi/libvmi.h>

static const char *mem_path = "/mem";
vmi_instance_t vmi = NULL;
vmi_init_data_t *init_data = NULL;

static int vmifs_getattr(const char *path, struct stat *stbuf)
{
    int res = 0;

    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else if (strcmp(path, mem_path) == 0) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = vmi_get_max_physical_address(vmi);
    } else
        res = -ENOENT;

    return res;
}

static int vmifs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    (void) fi;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, mem_path + 1, NULL, 0);

    return 0;
}

static int vmifs_open(const char *path, struct fuse_file_info *fi)
{
    if (strcmp(path, mem_path) != 0)
        return -ENOENT;

    uint32_t accmod = O_RDONLY | O_WRONLY | O_RDWR;
    if ((fi->flags & accmod) != O_RDONLY)
        return -EACCES;

    return 0;
}

static int vmifs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    (void) fi;
    if (strcmp(path, mem_path) != 0)
        return -ENOENT;

    uint64_t memsize = vmi_get_max_physical_address(vmi);
    if (offset >= 0 && ((uint64_t) offset) < memsize && size) {
        if (offset + size > memsize)
            size = memsize-offset;

        uint8_t *buffer = g_try_malloc0(sizeof(uint8_t)*size);
        size_t rsize = 0;
        if ( VMI_FAILURE == vmi_read_pa(vmi, offset, size, buffer, &rsize) ) {
            if (rsize > 0 && rsize <= size)
                memcpy(buf, buffer, rsize);
            g_free(buffer);
        } else {
            memcpy(buf, buffer, size);
            g_free(buffer);
        }

    } else {
        return 0;
    }

    return size;
}

void vmifs_destroy()
{
    if (vmi)
        vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }
}

static struct fuse_operations vmifs_oper = {
    .getattr    = vmifs_getattr,
    .readdir    = vmifs_readdir,
    .open   = vmifs_open,
    .read   = vmifs_read,
    .destroy   = vmifs_destroy,
};

int main(int argc, char *argv[])
{
    /* this is the VM or file that we are looking at */
    if (argc != 4 && argc != 5) {
        printf("Usage: %s name|domid <name|domid> <path> [<socket>]\n", argv[0]);
        return 1;
    }

    vmi_mode_t mode;
    uint64_t init_flags;
    uint64_t domid = VMI_INVALID_DOMID;
    void *domain;

    if (strcmp(argv[1],"name")==0) {
        init_flags = VMI_INIT_DOMAINNAME;
        domain = (void*)argv[2];
    } else if (strcmp(argv[1],"domid")==0) {
        init_flags = VMI_INIT_DOMAINID;
        domid = strtoull(argv[2], NULL, 0);
        domain = (void*)&domid;
    } else {
        printf("You have to specify either name or domid!\n");
        return 1;
    }

    if (argc == 5) {
        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(argv[4]);
    }

    if (VMI_FAILURE == vmi_get_access_mode(NULL, domain, init_flags, init_data, &mode)) {
        vmifs_destroy();
        return 1;
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, domain, init_flags, init_data, NULL)) {
        printf("Failed to init LibVMI library.\n");
        vmifs_destroy();
        return 1;
    }

    char *fuse_argv[2] = { argv[0], argv[3] };

    return fuse_main(2, fuse_argv, &vmifs_oper);
}

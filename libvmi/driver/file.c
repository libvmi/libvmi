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
#include "driver/file.h"
#include "driver/interface.h"
#include "driver/memory_cache.h"

#if ENABLE_FILE == 1
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <features.h>

// Use mmap() if this evaluates to true; otherwise, use a file pointer with
// seek/read
#define USE_MMAP 1


//----------------------------------------------------------------------------
// File-Specific Interface Functions (no direction mapping to driver_*)

static file_instance_t *file_get_instance (vmi_instance_t vmi)
{
    return ((file_instance_t *) vmi->driver);
}

void *file_get_memory (vmi_instance_t vmi, addr_t paddr, uint32_t length)
{
    void *memory = 0;

    if (paddr + length >= vmi->size) {
        dbprint ("--%s: request for PA range [0x%.16x-0x%.16x] reads past end of file\n",
                 __FUNCTION__, paddr, paddr+length);
        goto error_noprint;
    } // if

    memory = safe_malloc(length);

#if USE_MMAP
    (void)memcpy(memory, ((uint8_t *)file_get_instance(vmi)->map) + paddr, length);
#else
    if (paddr != lseek(file_get_instance(vmi)->fd, paddr, SEEK_SET)){
        goto error_print;
    }
    if (length != read(file_get_instance(vmi)->fd, memory, length)){
        goto error_print;
    }
#endif // USE_MMAP

    return memory;

error_print:
    dbprint ("%s: failed to read %d bytes at "
             "PA (offset) 0x%.16llx [VM size 0x%.16llx]\n",
             __FUNCTION__, length, paddr, vmi->size);
error_noprint:
    if (memory) free(memory);
    return NULL;
}

void file_release_memory (void *memory, size_t length)
{
    if (memory) free(memory);
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t file_init (vmi_instance_t vmi)
{
    FILE *fhandle = NULL;
    int fd = -1;
    file_instance_t * fi = file_get_instance(vmi);

    /* open handle to memory file */
    if ((fhandle = fopen(fi->filename, "rb")) == NULL){
        errprint("Failed to open file for reading.\n");
        goto fail;
    }
    fd = fileno(fhandle);

    fi->fhandle = fhandle;
    fi->fd      = fd;
    memory_cache_init(vmi, file_get_memory, file_release_memory, ULONG_MAX);

#if USE_MMAP
    /* try memory mapped file I/O */
    unsigned long size;
    if (VMI_FAILURE == file_get_memsize(vmi, &size)) {
        goto fail;
    } // if

    int mmap_flags = (MAP_PRIVATE | MAP_NORESERVE | MAP_POPULATE);

#ifdef MMAP_HUGETLB // since kernel 2.6.32
    mmap_flags |= MMAP_HUGETLB;
#endif // MMAP_HUGETLB

    void *map = mmap(NULL,                // addr
                     size,                // len
                     PROT_READ,           // prot
                     mmap_flags,          // flags
                     fd,                  // file descriptor
                     (off_t) 0);          // offset
    if (MAP_FAILED == map){
        perror("Failed to mmap file");
        goto fail;
    }
    fi->map = map;

    // Note: madvise(.., MADV_SEQUENTIAL | MADV_WILLNEED) does not seem to
    // improve performance

#endif  // USE_MMAP

    return VMI_SUCCESS;

fail:
    file_destroy(vmi);
    return VMI_FAILURE;
}

void file_destroy (vmi_instance_t vmi)
{
    file_instance_t * fi = file_get_instance(vmi);
#if USE_MMAP
    if (fi->map) {
        (void)munmap(fi->map, vmi->size);
        fi->map = 0;
    }
#endif  // USE_MMAP
    if (fi->fhandle) {
        fclose(fi->fhandle);
        fi->fhandle = 0;
        fi->fd = 0;
    }
}

void file_set_name (vmi_instance_t vmi, char *name)
{
    file_get_instance(vmi)->filename = strndup(name, 500);
}

status_t file_get_memsize (vmi_instance_t vmi, unsigned long *size)
{
    status_t ret = VMI_FAILURE;
    struct stat s;

    if (fstat(file_get_instance(vmi)->fd, &s) == -1){
        errprint("Failed to stat file.\n");
        goto error_exit;
    }
    *size = (unsigned long) s.st_size;
    ret = VMI_SUCCESS;

error_exit:
    return ret;
}

status_t file_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    switch (reg){
        case CR3:
            if (vmi->kpgd){
                *value = vmi->kpgd;
            }
            else if (vmi->cr3){
                *value = vmi->cr3;
            }
            else{
                goto error_exit;
            }
            break;
        default:
            goto error_exit;
            break;
    }

    return VMI_SUCCESS;
error_exit:
    return VMI_FAILURE;
}

addr_t file_pfn_to_mfn (vmi_instance_t vmi, addr_t pfn)
{
    return pfn;
}

void *file_read_page (vmi_instance_t vmi, addr_t page)
{
    addr_t paddr = page << vmi->page_shift;
    uint32_t offset = 0;
    return memory_cache_insert(vmi, paddr, &offset);
}

//TODO decide if this functionality makes sense for files
status_t file_write (vmi_instance_t vmi, addr_t paddr, void *buf, uint32_t length)
{
    return VMI_FAILURE;
}

int file_is_pv (vmi_instance_t vmi)
{
    return 0;
}

status_t file_test (unsigned long id, char *name)
{
    status_t ret = VMI_FAILURE;
    FILE *f = NULL;
    struct stat s;

    if (NULL == name){
        goto error_exit;
    }
    if ((f = fopen(name, "rb")) == NULL){
        goto error_exit;
    }
    if (fstat(fileno(f), &s) == -1){
        goto error_exit;
    }
    if (!s.st_size){
        goto error_exit;
    }
    ret = VMI_SUCCESS;

error_exit:
    if (f) fclose(f);
    return ret;
}

status_t file_pause_vm (vmi_instance_t vmi)
{
    return VMI_SUCCESS;
}

status_t file_resume_vm (vmi_instance_t vmi)
{
    return VMI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////
#else

status_t file_init (vmi_instance_t vmi) {return VMI_FAILURE; }
void file_destroy (vmi_instance_t vmi) { return; }
void file_set_name (vmi_instance_t vmi, char *name) {return; }
status_t file_get_memsize (vmi_instance_t vmi, unsigned long size) { return VMI_FAILURE; }
status_t file_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu) { return VMI_FAILURE; }
unsigned long file_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn) { return 0 };
void *file_read_page (vmi_instance_t vmi, unsigned long page) { return NULL; }
status_t file_write (vmi_instance_t vmi, addr_t paddr, void *buf, uint32_t length) { return VMI_FAILURE; }
int file_is_pv (vmi_instance_t vmi) { return 0; }
status_t file_test (unsigned long id, char *name) { return VMI_FAILURE; }
status_t file_pause_vm (vmi_instance_t vmi) { return VMI_FAILURE; }
status_t file_resume_vm (vmi_instance_t vmi) { return VMI_FAILURE; }

#endif /* ENABLE_FILE */

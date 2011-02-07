/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include "libvmi.h"
#include "private.h"
#include "driver/file.h"
#include "driver/interface.h"

#ifdef ENABLE_FILE
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

//----------------------------------------------------------------------------
// File-Specific Interface Functions (no direction mapping to driver_*)

static file_instance_t *file_get_instance (vmi_instance_t vmi)
{
    return ((file_instance_t *) vmi->driver);
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t file_init (vmi_instance_t vmi)
{
    FILE *fhandle = NULL;

    /* open handle to memory file */
    if ((fhandle = fopen(file_get_instance(vmi)->filename, "rb")) == NULL){
        errprint("Failed to open file for reading.\n");
        return VMI_FAILURE;
    }
    file_get_instance(vmi)->fhandle = fhandle;

}

void file_destroy (vmi_instance_t vmi)
{
    fclose(file_get_instance(vmi)->fhandle);
}

void file_set_name (vmi_instance_t vmi, char *name)
{
    file_get_instance(vmi)->filename = strndup(name, 500);
}

status_t file_get_memsize (vmi_instance_t vmi, unsigned long *size)
{
    status_t ret = VMI_FAILURE;
    struct stat s;

    if (fstat(fileno(file_get_instance(vmi)->fhandle), &s) == -1){
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
                *value = vmi->kpgd - vmi->page_offset;
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

unsigned long file_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn)
{
    return pfn;
}

void *file_map_page (vmi_instance_t vmi, int prot, unsigned long page)
{
    void *memory = NULL;
    long address = page << vmi->page_shift;
    int fildes = fileno(file_get_instance(vmi)->fhandle);

    if (address >= vmi->size){
        return NULL;
    }

    memory = mmap(NULL, vmi->page_size, prot, MAP_SHARED, fildes, address);
    if (MAP_FAILED == memory){
        errprint("File mmap failed.\n");
        return NULL;
    }
    return memory;
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

//////////////////////////////////////////////////////////////////////
#else

status_t file_init (vmi_instance_t vmi) {return VMI_FAILURE; }
void file_destroy (vmi_instance_t vmi) { return; }
void file_set_name (vmi_instance_t vmi, char *name) {return; }
status_t file_get_memsize (vmi_instance_t vmi, unsigned long size) { return VMI_FAILURE; }
status_t file_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu) { return VMI_FAILURE; }
unsigned long file_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn) { return 0 };
void *file_map_page (vmi_instance_t vmi, int prot, unsigned long page) { return NULL; }
int file_is_pv (vmi_instance_t vmi) { return 0; }
status_t file_test (unsigned long id, char *name) { return VMI_FAILURE; }

#endif /* ENABLE_FILE */

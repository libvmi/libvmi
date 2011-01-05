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
#include "driver/interface.h"
#include "config/config_parser.h"
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <fnmatch.h>

int read_config_file (vmi_instance_t vmi)
{
    extern FILE *yyin;
    int ret = VMI_SUCCESS;
    vmi_config_entry_t *entry;
    char *tmp = NULL;

    yyin = fopen("/etc/libvmi.conf", "r");
    if (NULL == yyin){
        fprintf(stderr, "ERROR: config file not found at /etc/libvmi.conf\n");
        ret = VMI_FAILURE;
        goto error_exit;
    }

    /* convert domain id to domain name for Xen mode */
    if (VMI_MODE_XEN == vmi->mode){
        if (driver_get_name(vmi, &vmi->image_type) == VMI_FAILURE){
            ret = VMI_FAILURE;
            goto error_exit;
        }
        dbprint("--got domain name from id (%d ==> %s).\n",
                driver_get_id(vmi),
                vmi->image_type);
    }

    if (vmi_parse_config(vmi->image_type)){
        errprint("Failed to read config file.\n");
        ret = VMI_FAILURE;
        goto error_exit;
    }
    entry = vmi_get_config();

    /* copy the values from entry into instance struct */
    vmi->sysmap = strdup(entry->sysmap);
    dbprint("--got sysmap from config (%s).\n", vmi->sysmap);
    
    if (strncmp(entry->ostype, "Linux", CONFIG_STR_LENGTH) == 0){
        vmi->os_type = VMI_OS_LINUX;
    }
    else if (strncmp(entry->ostype, "Windows", CONFIG_STR_LENGTH) == 0){
        vmi->os_type = VMI_OS_WINDOWS;
    }
    else{
        errprint("Unknown or undefined OS type.\n");
        ret = VMI_FAILURE;
        goto error_exit;
    }

    /* Copy config info based on OS type */
    if(VMI_OS_LINUX == vmi->os_type){
        dbprint("--reading in linux offsets from config file.\n");
        if(entry->offsets.linux_offsets.tasks){
            vmi->os.linux_instance.tasks_offset =
                 entry->offsets.linux_offsets.tasks;
        }

        if(entry->offsets.linux_offsets.mm){
            vmi->os.linux_instance.mm_offset =
                entry->offsets.linux_offsets.mm;
        }

        if(entry->offsets.linux_offsets.pid){
            vmi->os.linux_instance.pid_offset =
                entry->offsets.linux_offsets.pid;
        }

        if(entry->offsets.linux_offsets.pgd){
            vmi->os.linux_instance.pgd_offset =
                entry->offsets.linux_offsets.pgd;
        }

        if(entry->offsets.linux_offsets.addr){
            vmi->os.linux_instance.addr_offset =
                entry->offsets.linux_offsets.addr;
        }
    }
    else if (VMI_OS_WINDOWS == vmi->os_type){
        dbprint("--reading in windows offsets from config file.\n");
        if(entry->offsets.windows_offsets.ntoskrnl){
          vmi->os.windows_instance.ntoskrnl =
                entry->offsets.windows_offsets.ntoskrnl;
        }

        if(entry->offsets.windows_offsets.tasks){
            vmi->os.windows_instance.tasks_offset =
                entry->offsets.windows_offsets.tasks;
        }

        if(entry->offsets.windows_offsets.pdbase){ 
            vmi->os.windows_instance.pdbase_offset =
                entry->offsets.windows_offsets.pdbase;
        }

        if(entry->offsets.windows_offsets.pid){
            vmi->os.windows_instance.pid_offset =
                entry->offsets.windows_offsets.pid;
        }

        if(entry->offsets.windows_offsets.peb){
            vmi->os.windows_instance.peb_offset =
                entry->offsets.windows_offsets.peb;
        }

        if(entry->offsets.windows_offsets.iba){
            vmi->os.windows_instance.iba_offset =
                entry->offsets.windows_offsets.iba;
        }

        if(entry->offsets.windows_offsets.ph){
            vmi->os.windows_instance.ph_offset =
                entry->offsets.windows_offsets.ph;
        }
    }

#ifdef VMI_DEBUG
    dbprint("--got ostype from config (%s).\n", entry->ostype);
    if (vmi->os_type == VMI_OS_LINUX){
        dbprint("**set os_type to Linux.\n");
    }
    else if (vmi->os_type == VMI_OS_WINDOWS){
        dbprint("**set os_type to Windows.\n");
    }
    else{
        dbprint("**set os_type to unknown.\n");
    }
#endif

error_exit:
    if (tmp) free(tmp);
    if (yyin) fclose(yyin);
    return ret;
}

/* check that this vm uses a paging method that we support */
//TODO add memory layout discovery here for file
int get_memory_layout (vmi_instance_t vmi)
{
    int ret = VMI_SUCCESS;
    reg_t cr0, cr3, cr4;

    /* get the control register values */
    if (driver_get_vcpureg(vmi, &cr0, REG_CR0, 0) == VMI_FAILURE){
        ret = VMI_FAILURE;
        goto error_exit;
    }
    if (driver_get_vcpureg(vmi, &cr3, REG_CR3, 0) == VMI_FAILURE){
        ret = VMI_FAILURE;
        goto error_exit;
    }
    if (driver_get_vcpureg(vmi, &cr4, REG_CR4, 0) == VMI_FAILURE){
        ret = VMI_FAILURE;
        goto error_exit;
    }

    /* PG Flag --> CR0, bit 31 == 1 --> paging enabled */
    if (!vmi_get_bit(cr0, 31)){
        errprint("Paging disabled for this VM, not supported.\n");
        ret = VMI_FAILURE;
        goto error_exit;
    }
    /* PAE Flag --> CR4, bit 5 == 0 --> pae disabled */
    vmi->pae = vmi_get_bit(cr4, 5);
    dbprint("**set pae = %d\n", vmi->pae);

    /* PSE Flag --> CR4, bit 4 == 0 --> pse disabled */
    vmi->pse = vmi_get_bit(cr4, 4);
    dbprint("**set pse = %d\n", vmi->pse);

    /* testing to see CR3 value */
    vmi->cr3 = cr3 & 0xFFFFF000;
    dbprint("**set cr3 = 0x%.8x\n", vmi->cr3);

error_exit:
    return ret;
}

void init_page_offset (vmi_instance_t vmi)
{
    //TODO need to actually determine these values instead of just guessing

    if (VMI_OS_LINUX == vmi->os_type){
        vmi->page_offset = 0xc0000000;
    }
    else if (VMI_OS_WINDOWS == vmi->os_type){
        vmi->page_offset = 0x80000000;
    }
    else{
        vmi->page_offset = 0;
    }
    dbprint("**set page_offset = 0x%.8x\n", vmi->page_offset);

    //TODO need a better way to handle the page size issue
    /* assume 4k pages for now, update when 4M page is found */
    vmi->page_shift = 12;
    vmi->page_size = 1 << vmi->page_shift;
}

int helper_init (vmi_instance_t vmi)
{
    int ret = VMI_SUCCESS;
    uint32_t local_offset = 0;
    unsigned char *memory = NULL;

    /* read in configure file information */
    if (read_config_file(vmi) == VMI_FAILURE){
        ret = vmi_report_error(vmi, 0, VMI_EMINOR);
        if (VMI_FAILURE == ret) goto error_exit;
    }
    
    /* determine the page sizes and layout for target OS */
    if (get_memory_layout(vmi) == VMI_FAILURE){
        warnprint("Memory layout not supported.\n");
        ret = vmi_report_error(vmi, 0, VMI_ECRITICAL);
        if (VMI_FAILURE == ret) goto error_exit;
    }
    dbprint("--got memory layout.\n");

    /* setup the correct page offset size for the target OS */
    init_page_offset(vmi);

    /* get the memory size */
    if (driver_get_memsize(vmi, &vmi->size) == VMI_FAILURE){
        errprint("Failed to get memory size.\n");
        ret = vmi_report_error(vmi, 0, VMI_ECRITICAL);
        if (VMI_FAILURE == ret) goto error_exit;
    }
    dbprint("**set size = %d\n", vmi->size);

    /* setup OS specific stuff */
    if (vmi->os_type == VMI_OS_LINUX){
        ret = linux_init(vmi);
    }
    else if (vmi->os_type == VMI_OS_WINDOWS){
        ret = windows_init(vmi);
    }

error_exit:
    return ret;
}

/* common code for all init functions */
void vmi_init_common (vmi_instance_t vmi)
{
    dbprint("LibVMI Devel Version\n");
    vmi->cache_head = NULL;
    vmi->cache_tail = NULL;
    vmi->current_cache_size = 0;
    vmi->pid_cache_head = NULL;
    vmi->pid_cache_tail = NULL;
    vmi->current_pid_cache_size = 0;
}

/* initialize to view an actively running VM */
status_t vmi_init_vm_private (
    unsigned long vmid,
    char *name,
    vmi_instance_t *vmi,
    uint32_t error_mode)
{
    /* allocate memory for the instance structure */
    *vmi = (vmi_instance_t) safe_malloc(sizeof(struct vmi_instance));

    /*TODO determine what vmm we are running on */
    (*vmi)->mode = VMI_MODE_XEN;
    dbprint("LibVMI Mode Xen\n");
    (*vmi)->error_mode = error_mode;
    dbprint("LibVMI Error Mode = %d\n", (*vmi)->error_mode);

    /* resolve vmid, if needed */
    if (!vmid && name){
        vmid = driver_get_id_from_name(*vmi, name);
        dbprint("--got id from name (%s --> %d)\n", name, vmid);
    }
    driver_set_id(*vmi, vmid);

    /* complete the init */
    if (driver_init(*vmi) == VMI_FAILURE){
        return VMI_FAILURE;
    }
    vmi_init_common(*vmi);
    return helper_init(*vmi);
}

/* initialize to view a file image */
int vmi_init_file_private (
    char *filename,
    char *image_type,
    vmi_instance_t *vmi,
    uint32_t error_mode)
{
#define MAX_IMAGE_TYPE_LEN 256
    *vmi = (vmi_instance_t) safe_malloc(sizeof(struct vmi_instance));
    (*vmi)->mode = VMI_MODE_FILE;
    dbprint("LibVMI Mode File\n");
    (*vmi)->error_mode = error_mode;
    dbprint("LibVMI Error Mode = %d\n", (*vmi)->error_mode);

    driver_set_name(*vmi, filename);
    if (driver_init(*vmi) == VMI_FAILURE){
        return VMI_FAILURE;
    }
    vmi_init_common(*vmi);
    (*vmi)->image_type = strndup(image_type, MAX_IMAGE_TYPE_LEN);
    return helper_init(*vmi);
}

/* below are stub init functions that are called by library users */
status_t vmi_init_vm_name_strict (char *name, vmi_instance_t *vmi)
{
    return vmi_init_vm_private(0, name, vmi, VMI_FAILHARD);
}

status_t vmi_init_vm_name_lax (char *name, vmi_instance_t *vmi)
{
    return vmi_init_vm_private(0, name, vmi, VMI_FAILSOFT);
}

status_t vmi_init_vm_id_strict (unsigned long id, vmi_instance_t *vmi)
{
    return vmi_init_vm_private(id, NULL, vmi, VMI_FAILHARD);
}

status_t vmi_init_vm_id_lax (unsigned long id, vmi_instance_t *vmi)
{
    return vmi_init_vm_private(id, NULL, vmi, VMI_FAILSOFT);
}

status_t vmi_init_file_strict (char *filename, char *image_type, vmi_instance_t *vmi)
{
    return vmi_init_file_private(filename, image_type, vmi, VMI_FAILHARD);
}
status_t vmi_init_file_lax (char *filename, char *image_type, vmi_instance_t *vmi)
{
    return vmi_init_file_private(filename, image_type, vmi, VMI_FAILSOFT);
}

status_t vmi_destroy (vmi_instance_t vmi)
{
    driver_destroy(vmi);
    vmi_destroy_cache(vmi);
    vmi_destroy_pid_cache(vmi);
    free(vmi);
    return VMI_SUCCESS;
}

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
#include <stdlib.h>
#include <limits.h>
#include <fnmatch.h>

extern FILE *yyin;

static int read_config_file (vmi_instance_t vmi)
{
    int ret = VMI_SUCCESS;
    vmi_config_entry_t *entry;
    char *tmp = NULL;

    yyin = fopen("/etc/libvmi.conf", "r");
    if (NULL == yyin){
        fprintf(stderr, "ERROR: config file not found at /etc/libvmi.conf\n");
        ret = VMI_FAILURE;
        goto error_exit;
    }

    if (vmi_parse_config(vmi->image_type) != 0){
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

static uint32_t find_cr3 (vmi_instance_t vmi)
{
    if (VMI_OS_WINDOWS == vmi->os_type){
        return windows_find_cr3(vmi);
    }
    else{
        errprint("find_kpgd not implemented for this target OS\n");
    }
}

/* check that this vm uses a paging method that we support */
static int get_memory_layout (vmi_instance_t vmi)
{
    int ret = VMI_SUCCESS;

    /* pull info from registers, if we can */
    reg_t cr0, cr3, cr4;

    /* get the control register values */
    if (driver_get_vcpureg(vmi, &cr0, CR0, 0) == VMI_FAILURE){
        goto backup_plan;
    }
    if (driver_get_vcpureg(vmi, &cr3, CR3, 0) == VMI_FAILURE){
        goto backup_plan;
    }
    if (driver_get_vcpureg(vmi, &cr4, CR4, 0) == VMI_FAILURE){
        goto backup_plan;
    }

    /* PG Flag --> CR0, bit 31 == 1 --> paging enabled */
    if (!vmi_get_bit(cr0, 31)){
        errprint("Paging disabled for this VM, not supported.\n");
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
    dbprint("--got memory layout.\n");
    return VMI_SUCCESS;

backup_plan:
    vmi->pae = 0;
    dbprint("**guessed pae = %d\n", vmi->pae);

    vmi->pse = 0;
    dbprint("**guessed pse = %d\n", vmi->pse);

    vmi->cr3 = find_cr3(vmi);
    dbprint("**set cr3 = 0x%.8x\n", vmi->cr3);
    return VMI_SUCCESS;

error_exit:
    return VMI_FAILURE;
}

static status_t init_page_offset (vmi_instance_t vmi)
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

    return VMI_SUCCESS;
}

static status_t set_driver_type (vmi_instance_t vmi, mode_t mode, unsigned long id, char *name)
{
    if (VMI_MODE_AUTO == mode){
        if (VMI_FAILURE == driver_init_mode(vmi, id, name)){
            errprint("Failed to identify correct mode.\n");
            return VMI_FAILURE;
        }
    }
    else{
        vmi->mode = mode;
    }
    dbprint("LibVMI Mode %d\n", vmi->mode);
    return VMI_SUCCESS;
}

/* the name passed may contain the full path and we just want the filename */
static void set_image_type_for_file (vmi_instance_t vmi, char *name)
{
    char *ptr = NULL;
    if ((ptr = strrchr(name, '/')) == NULL){
        ptr = name;
    }
    else{
        ptr++;
    }
    vmi->image_type = strndup(ptr, 100);
}

static status_t set_id_and_name (vmi_instance_t vmi, mode_t mode, unsigned long id, char *name)
{
    if (VMI_MODE_FILE == vmi->mode){
        if (name){
            set_image_type_for_file(vmi, name);
            driver_set_name(vmi, name);
        }
        else{
            errprint("Must specify name for file mode.\n");
            return VMI_FAILURE;
        }
    }
    else{
        /* resolve and set id and name */
        if (!id){
            if (name){
                id = driver_get_id_from_name(vmi, name);
                dbprint("--got id from name (%s --> %d)\n", name, id);
                driver_set_id(vmi, id);
            }
            else{
                errprint("Must specifiy either id or name.\n");
                return VMI_FAILURE;
            }
        }
        else{
            driver_set_id(vmi, id);
            if (name){
                errprint("Specifying both id and name is undefined.\n");
                return VMI_FAILURE;
            }
            else{
                if (VMI_FAILURE == driver_get_name(vmi, &name)){
                    errprint("Invalid id.\n");
                    return VMI_FAILURE;
                }
            }
        }
        vmi->image_type = strndup(name, 100);
        driver_set_name(vmi, name);
    }
    dbprint("**set image_type = %s\n", vmi->image_type);
    return VMI_SUCCESS;
}

static void vmi_init_common (vmi_instance_t vmi)
{
    dbprint("LibVMI Devel Version\n");  //TODO change this with each release
    vmi->cache_head = NULL;
    vmi->cache_tail = NULL;
    vmi->current_cache_size = 0;
    vmi->pid_cache_head = NULL;
    vmi->pid_cache_tail = NULL;
    vmi->current_pid_cache_size = 0;
}

static status_t vmi_init_private (vmi_instance_t *vmi, mode_t mode, unsigned long id, char *name)
{
    /* allocate memory for instance structure */
    *vmi = (vmi_instance_t) safe_malloc(sizeof(struct vmi_instance));

    /* initialize instance struct to default values */
    vmi_init_common(*vmi);

    /* connecting to xen, kvm, file, etc */
    if (VMI_FAILURE == set_driver_type(*vmi, mode, id, name)){
        goto error_exit;
    }

    /* resolve the id and name */
    if (VMI_FAILURE == set_id_and_name(*vmi, mode, id, name)){
        goto error_exit;
    }

    /* driver-specific initilization */
    if (VMI_FAILURE == driver_init(*vmi)){
        goto error_exit;
    }
    dbprint("--completed driver init.\n");

    /* read and parse the config file */
    if (VMI_FAILURE == read_config_file(*vmi)){
        goto error_exit;
    }
    
    /* setup the correct page offset size for the target OS */
    if (VMI_FAILURE == init_page_offset(*vmi)){
        goto error_exit;
    }

    /* get the memory size */
    if (driver_get_memsize(*vmi, &(*vmi)->size) == VMI_FAILURE){
        errprint("Failed to get memory size.\n");
        goto error_exit;
    }
    dbprint("**set size = %d\n", (*vmi)->size);

    /* determine the page sizes and layout for target OS */
    if (VMI_FAILURE == get_memory_layout(*vmi)){
        errprint("Memory layout not supported.\n");
        goto error_exit;
    }

    /* setup OS specific stuff */
    if (VMI_OS_LINUX == (*vmi)->os_type){
        return linux_init(*vmi);
    }
    else if (VMI_OS_WINDOWS == (*vmi)->os_type){
        return windows_init(*vmi);
    }

error_exit:
    return VMI_FAILURE;
}

status_t vmi_init (vmi_instance_t *vmi, mode_t mode, char *name)
{
    return vmi_init_private(vmi, mode, 0, name);
}

status_t vmi_destroy (vmi_instance_t vmi)
{
    driver_destroy(vmi);
    vmi_destroy_cache(vmi);
    vmi_destroy_pid_cache(vmi);
    if (vmi) free(vmi);
    return VMI_SUCCESS;
}

/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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
#include "driver/interface.h"
#include "driver/memory_cache.h"
#include "os/os_interface.h"
#include "os/windows/windows.h"
#include "os/linux/linux.h"
#include "config/config_parser.h"
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <limits.h>
#include <fnmatch.h>
#include <sys/types.h>
#include <pwd.h>

extern FILE *yyin;

static FILE *
open_config_file(
    )
{
    FILE *f = NULL;
    char location[100];
    char *sudo_user = NULL;
    struct passwd *pw_entry = NULL;

    /* first check home directory of sudo user */
    if ((sudo_user = getenv("SUDO_USER")) != NULL) {
        if ((pw_entry = getpwnam(sudo_user)) != NULL) {
            snprintf(location, 100, "%s/etc/libvmi.conf\0",
                     pw_entry->pw_dir);
            dbprint("--looking for config file at %s\n", location);
            if ((f = fopen(location, "r")) != NULL) {
                goto success;
            }
        }
    }

    /* next check home directory for current user */
    snprintf(location, 100, "%s/etc/libvmi.conf\0", getenv("HOME"));
    dbprint("--looking for config file at %s\n", location);
    if ((f = fopen(location, "r")) != NULL) {
        goto success;
    }

    /* finally check in /etc */
    snprintf(location, 100, "/etc/libvmi.conf\0");
    dbprint("--looking for config file at %s\n", location);
    if ((f = fopen(location, "r")) != NULL) {
        goto success;
    }

    return NULL;
success:
    dbprint("**Using config file at %s\n", location);
    return f;
}

status_t
set_os_type_from_config(
    vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;
    GHashTable *configtbl = (GHashTable *)vmi->config;
    const char* ostype = NULL;

    vmi->os_type = VMI_OS_UNKNOWN;
    if (vmi->os_data) {
        free(vmi->os_data);
        vmi->os_data = NULL;
    }

    ostype = g_hash_table_lookup(configtbl, "ostype");
    if (ostype == NULL) {
        ostype = g_hash_table_lookup(configtbl, "os_type");
    }

    if (ostype == NULL) {
        errprint("Undefined OS type!\n");
        return VMI_FAILURE;
    }

    if (strncmp(ostype, "Linux", CONFIG_STR_LENGTH) == 0) {
        vmi->os_type = VMI_OS_LINUX;
        ret = VMI_SUCCESS;
    } else if (strncmp(ostype, "Windows", CONFIG_STR_LENGTH) == 0) {
        vmi->os_type = VMI_OS_WINDOWS;
        ret = VMI_SUCCESS;
    } else {
        errprint("VMI_ERROR: Unknown OS type: %s!\n", ostype);
        ret = VMI_FAILURE;
    }

    return ret;
}

status_t
read_config_file(
    vmi_instance_t vmi, FILE* config_file);

status_t read_config_string(vmi_instance_t vmi,
        const char *config) {
    status_t ret = VMI_SUCCESS;
    FILE* config_file = NULL;

    if (config == NULL) {
        errprint("VMI_ERROR: NULL string passed for VMI_CONFIG_STRING\n");
        return VMI_FAILURE;
    }

    int length = strlen(config) + strlen(vmi->image_type) + 2;
    char *config_str = safe_malloc(length);

    sprintf(config_str, "%s %s\0", vmi->image_type, config);

    config_file = fmemopen(config_str, strlen(config_str), "r");

    ret = read_config_file(vmi, config_file);

    return ret;
}

status_t read_config_file_entry(vmi_instance_t vmi) {
    status_t ret = VMI_FAILURE;
    FILE* config_file = NULL;

    config_file = open_config_file();
    if (NULL == config_file) {
        fprintf(stderr, "ERROR: config file not found.\n");
        ret = VMI_FAILURE;
        return ret;
    }

    ret = read_config_file(vmi, config_file);

    return ret;
}

status_t
read_config_file(
    vmi_instance_t vmi, FILE* config_file)
{
    status_t ret = VMI_SUCCESS;

    yyin = config_file;

    if (vmi_parse_config(vmi->image_type) != 0) {
        errprint("Failed to read config file.\n");
        ret = VMI_FAILURE;
        goto error_exit;
    }
    vmi->config = vmi_get_config();

    if (vmi->config == NULL) {
        errprint("No entry in config file for %s.\n", vmi->image_type);
        ret = VMI_FAILURE;
        goto error_exit;
    } else {
        ret = VMI_SUCCESS;
    }

#ifdef VMI_DEBUG
    if (vmi->os_type == VMI_OS_LINUX) {
        dbprint("**set os_type to Linux.\n");
    }
    else if (vmi->os_type == VMI_OS_WINDOWS) {
        dbprint("**set os_type to Windows.\n");
    }
    else {
        dbprint("**set os_type to unknown.\n");
    }
#endif

error_exit:
    if (config_file)
        fclose(config_file);
    return ret;
}

/*
 * check that this vm uses a paging method that we support
 * and set pm/cr3/pae/pse/lme flags optionally on the given pointers
 */
status_t
get_memory_layout(
    vmi_instance_t vmi,
    page_mode_t *set_pm,
    int *set_pae,
    int *set_pse,
    int *set_lme)
{
    // To get the paging layout, the following bits are needed:
    // 1. CR0.PG
    // 2. CR4.PAE
    // 3. Either (a) IA32_EFER.LME, or (b) the guest's address width (32 or
    //    64). Not all backends allow us to read an MSR; in particular, Xen's PV
    //    backend doessn't.

    status_t ret = VMI_FAILURE;
    page_mode_t pm = VMI_PM_UNKNOWN;
    uint8_t dom_addr_width = 0; // domain address width (bytes)

    /* pull info from registers, if we can */
    reg_t cr0, cr3, cr4, efer;
    int pae, pse, lme;
    uint8_t msr_efer_lme = 0;   // LME bit in MSR_EFER

    /* skip all of this for files */
    if (VMI_FILE == vmi->mode) {
        goto _exit;
    }

    /* get the control register values */
    if (driver_get_vcpureg(vmi, &cr0, CR0, 0) == VMI_FAILURE) {
        errprint("**failed to get CR0\n");
        goto _exit;
    }

    /* PG Flag --> CR0, bit 31 == 1 --> paging enabled */
    if (!vmi_get_bit(cr0, 31)) {
        errprint("Paging disabled for this VM, not supported.\n");
        goto _exit;
    }

    //
    // Paging enabled (PG==1)
    //
    if (driver_get_vcpureg(vmi, &cr4, CR4, 0) == VMI_FAILURE) {
        errprint("**failed to get CR4\n");
        goto _exit;
    }

    /* PSE Flag --> CR4, bit 5 */
    pae = vmi_get_bit(cr4, 5);
    dbprint("**set pae = %d\n", pae);

    /* PSE Flag --> CR4, bit 4 */
    pse = vmi_get_bit(cr4, 4);
    dbprint("**set pse = %d\n", pse);

    ret = driver_get_vcpureg(vmi, &efer, MSR_EFER, 0);
    if (VMI_SUCCESS == ret) {
        lme = vmi_get_bit(efer, 8);
        dbprint("**set lme = %d\n", lme);
    }
    else {
        dbprint("**failed to get MSR_EFER, trying method #2\n");

        // does this trick work in all cases?
        ret = driver_get_address_width(vmi, &dom_addr_width);
        if (VMI_FAILURE == ret) {
            errprint
                ("Failed to get domain address width. Giving up.\n");
            goto _exit;
        }
        lme = (8 == dom_addr_width);
        dbprint
            ("**found guest address width is %d bytes; assuming IA32_EFER.LME = %d\n",
             dom_addr_width, lme);
    }   // if


    // Get current cr3 for sanity checking
    if (driver_get_vcpureg(vmi, &cr3, CR3, 0) == VMI_FAILURE) {
        errprint("**failed to get CR3\n");
        goto _exit;
    }

    // now determine addressing mode
    if (0 == pae) {
        dbprint("**32-bit paging\n");
        pm = VMI_PM_LEGACY;
        cr3 &= 0xFFFFF000ull;
    }
    // PAE == 1; determine IA-32e or PAE
    else if (lme) {    // PAE == 1, LME == 1
        dbprint("**IA-32e paging\n");
        pm = VMI_PM_IA32E;
        cr3 &= 0xFFFFFFFFFFFFF000ull;
    }
    else {  // PAE == 1, LME == 0
        dbprint("**PAE paging\n");
        pm = VMI_PM_PAE;
        cr3 &= 0xFFFFFFE0;
    }   // if-else
    dbprint("**sanity checking cr3 = 0x%.16"PRIx64"\n", cr3);

    /* testing to see CR3 value */
    if (!driver_is_pv(vmi) && cr3 > vmi->size) {   // sanity check on CR3
        dbprint("** Note cr3 value [0x%"PRIx64"] exceeds memsize [0x%"PRIx64"]\n",
                cr3, vmi->size);
    }

    if(set_pm != NULL) {
        *set_pm=pm;
    }
    if(set_pae != NULL) {
        *set_pae=pae;
    }
    if(set_pse != NULL) {
        *set_pse=pse;
    }
    if(set_lme != NULL) {
         *set_lme=lme;
    }

_exit:
    return ret;
}

static status_t
init_page_offset(
    vmi_instance_t vmi)
{
    //TODO need to actually determine these values instead of just guessing
    //TODO need a better way to handle the page size issue
    /* assume 4k pages for now, update when 2M page is found */
    vmi->page_shift = 12;
    vmi->page_size = 1 << vmi->page_shift;

    return VMI_SUCCESS;
}

static status_t
set_driver_type(
    vmi_instance_t vmi,
    vmi_mode_t mode,
    unsigned long id,
    char *name)
{
    if (VMI_AUTO == mode) {
        if (VMI_FAILURE == driver_init_mode(vmi, id, name)) {
            errprint("Failed to identify correct mode.\n");
            return VMI_FAILURE;
        }
    }
    else {
        vmi->mode = mode;
    }
    dbprint("LibVMI Mode %d\n", vmi->mode);
    return VMI_SUCCESS;
}

/* the name passed may contain the full path and we just want the filename */
static void
set_image_type_for_file(
    vmi_instance_t vmi,
    char *name)
{
    char *ptr = NULL;

    if ((ptr = strrchr(name, '/')) == NULL) {
        ptr = name;
    }
    else {
        ptr++;
    }
    vmi->image_type = strndup(ptr, 500);
    vmi->image_type_complete = strndup(name, 500);
}

static status_t
set_id_and_name(
    vmi_instance_t vmi,
    vmi_mode_t mode,
    unsigned long id,
    char *name)
{
    if (VMI_FILE == vmi->mode) {
        if (name) {
            set_image_type_for_file(vmi, name);
            driver_set_name(vmi, name);
        }
        else {
            errprint("Must specify name for file mode.\n");
            return VMI_FAILURE;
        }
    }
    else {
        /* resolve and set id and name */
        if (VMI_INVALID_DOMID == id) {
            if (name) {
                if (VMI_INVALID_DOMID != (id = driver_get_id_from_name(vmi, name)) ) {
                    dbprint("--got id from name (%s --> %lu)\n", name, id);
                    driver_set_id(vmi, id);
                } else {
                    errprint("Failed to get domain id from name.\n");
                    return VMI_FAILURE;
                }
            }
            else {
                errprint("Must specifiy either id or name.\n");
                return VMI_FAILURE;
            }
        }
        else {
            if (name) {
                errprint("Specifying both id and name is undefined.\n");
                return VMI_FAILURE;
            }

            if(VMI_FAILURE == driver_check_id(vmi,id)) {
                errprint("Invalid id.\n");
                return VMI_FAILURE;
            }

            driver_set_id(vmi, id);

            if (VMI_FAILURE != driver_get_name_from_id(vmi, id, &name)) {
                dbprint("--got name from id (%lu --> %s)\n", id, name);
            } else {
                dbprint("--failed to get domain name from id!\n");

                // Only under Xen this is OK
                if(vmi->mode != VMI_XEN) {
                    return VMI_FAILURE;
                }
            }
        }

        if(name != NULL) {
            vmi->image_type = name;
            driver_set_name(vmi, name);
        } else {
            // create placeholder for image_type
            char *idstring = malloc(snprintf(NULL, 0, "domid-%lu", id) + 1);
            sprintf(idstring, "domid-%lu", id);
            vmi->image_type = idstring;
        }
    }
    dbprint("**set image_type = %s\n", vmi->image_type);
    return VMI_SUCCESS;
}

static status_t
vmi_init_private(
    vmi_instance_t *vmi,
    uint32_t flags,
    unsigned long id,
    char *name,
    vmi_config_t *config)
{
    uint32_t access_mode = flags & 0x0000FFFF;
    uint32_t init_mode = flags & 0x00FF0000;
    uint32_t config_mode = flags & 0xFF000000;
    status_t status = VMI_FAILURE;

    /* allocate memory for instance structure */
    *vmi = (vmi_instance_t) safe_malloc(sizeof(struct vmi_instance));
    memset(*vmi, 0, sizeof(struct vmi_instance));

    /* initialize instance struct to default values */
    dbprint("LibVMI Version 0.11.0\n");  //TODO change this with each release

    /* save the flags and init mode */
    (*vmi)->flags = flags;
    (*vmi)->init_mode = init_mode;
    (*vmi)->config_mode = config_mode;

    /* the config hash table is set up later based on mode */
    (*vmi)->config = NULL;

    /* setup the caches */
    pid_cache_init(*vmi);
    sym_cache_init(*vmi);
    rva_cache_init(*vmi);
    v2p_cache_init(*vmi);
#if ENABLE_SHM_SNAPSHOT == 1
    v2m_cache_init(*vmi);
#endif

    /* connecting to xen, kvm, file, etc */
    if (VMI_FAILURE == set_driver_type(*vmi, access_mode, id, name)) {
        goto error_exit;
    }

    /* resolve the id and name */
    if (VMI_FAILURE == set_id_and_name(*vmi, access_mode, id, name)) {
        goto error_exit;
    }

    /* driver-specific initilization */
    if (VMI_FAILURE == driver_init(*vmi)) {
        goto error_exit;
    }
    dbprint("--completed driver init.\n");

    /* we check VMI_INIT_COMPLETE first as
       VMI_INIT_PARTIAL is not exclusive */
    if (init_mode & VMI_INIT_COMPLETE) {

        /* init_complete requires configuration */
        if(VMI_CONFIG_NONE & (*vmi)->config_mode) {
            /* falling back to VMI_CONFIG_GLOBAL_FILE_ENTRY is unsafe here
                as the config pointer is probably NULL */
            goto error_exit;
        }

        /* read and parse the config file */
        if ( (VMI_CONFIG_STRING & (*vmi)->config_mode)
                 && VMI_FAILURE == read_config_string(*vmi, (char*)config)) {
            goto error_exit;
        }

        if ( (VMI_CONFIG_GLOBAL_FILE_ENTRY & (*vmi)->config_mode)
                 && VMI_FAILURE == read_config_file_entry(*vmi)) {
            goto error_exit;
        }

        /* read and parse the ghashtable */
        if ((VMI_CONFIG_GHASHTABLE & (*vmi)->config_mode)) {
            (*vmi)->config = (GHashTable*)config;
        }

        if(VMI_FAILURE == set_os_type_from_config(*vmi)) {
            dbprint("--failed to determind os type from ghashtable\n");
            goto error_exit;
        }


        /* setup the correct page offset size for the target OS */
        if (VMI_FAILURE == init_page_offset(*vmi)) {
            goto error_exit;
        }

        /* get the memory size */
        if (driver_get_memsize(*vmi, &(*vmi)->size) == VMI_FAILURE) {
            errprint("Failed to get memory size.\n");
            goto error_exit;
        }
        dbprint("**set size = %"PRIu64" [0x%"PRIx64"]\n", (*vmi)->size,
                (*vmi)->size);

        /* determine the page sizes and layout for target OS */

        // Find the memory layout. If this fails, then proceed with the
        // OS-specific heuristic techniques.
        (*vmi)->pae = (*vmi)->pse = (*vmi)->lme = 0;
        (*vmi)->page_mode = VMI_PM_UNKNOWN;

        if ((*vmi)->mode == VMI_FILE) {
            dbprint(
                    "**Can't get memory layout for VMI_FILE. Trying heuristic methods, if any.\n");
        } else {
            status = get_memory_layout(*vmi, &((*vmi)->page_mode),
                    &((*vmi)->pae), &((*vmi)->pse), &((*vmi)->lme));

            if (VMI_FAILURE == status) {
                dbprint(
                        "**Failed to get memory layout for VM. Trying OS heuristic methods, if any.\n");
                // fall-through
            }   // if
        }

        /* setup OS specific stuff */
        if (VMI_OS_LINUX == (*vmi)->os_type) {
            status = linux_init(*vmi);
        }
        else if (VMI_OS_WINDOWS == (*vmi)->os_type) {
            status = windows_init(*vmi);
        }

        /* Enable event handlers only if we're in a consistent state */
        if((status == VMI_SUCCESS) && (init_mode & VMI_INIT_EVENTS)){
            events_init(*vmi);
        }

        return status;
    } else if (init_mode & VMI_INIT_PARTIAL) {
        init_page_offset(*vmi);
        driver_get_memsize(*vmi, &(*vmi)->size);

        /* Enable event handlers */
        if(init_mode & VMI_INIT_EVENTS){
            events_init(*vmi);
        }

        return VMI_SUCCESS;
    }

error_exit:
    return status;
}

status_t
vmi_init(
    vmi_instance_t *vmi,
    uint32_t flags,
    char *name)
{
    return vmi_init_private(vmi, flags | VMI_CONFIG_GLOBAL_FILE_ENTRY, VMI_INVALID_DOMID, name, NULL);
}

status_t
vmi_init_custom(
    vmi_instance_t *vmi,
    uint32_t flags,
    vmi_config_t config)
{
    status_t ret = VMI_FAILURE;
    uint32_t config_mode = flags & 0xFF000000;

    if (NULL == config) {
        config_mode |= VMI_CONFIG_NONE;
    }

    if (VMI_CONFIG_GLOBAL_FILE_ENTRY == config_mode) {

        ret = vmi_init(vmi, flags, (char *)config);
        goto _done;

    } else if (VMI_CONFIG_STRING == config_mode) {
        char *name = NULL;

        if (VMI_FILE == (*vmi)->mode) {
            name = strdup((*vmi)->image_type_complete);
        } else {
            name = strdup((*vmi)->image_type);
        }

        ret = vmi_init_private(vmi, flags, VMI_INVALID_DOMID, name,
                (vmi_config_t)config);

    } else if (VMI_CONFIG_GHASHTABLE == config_mode) {

        char *name = NULL;
        unsigned long domid = VMI_INVALID_DOMID;
        GHashTable *configtbl = (GHashTable *)config;
        gpointer idptr = NULL;

        name = (char *)g_hash_table_lookup(configtbl, "name");
        if(g_hash_table_lookup_extended(configtbl, "domid", NULL, &idptr)) {
            domid = *(unsigned long *)idptr;
        }

        if (name != NULL && domid != VMI_INVALID_DOMID) {
            errprint("--specifying both the name and domid is not supported\n");
        } else if (name != NULL) {
            ret = vmi_init_private(vmi, flags, VMI_INVALID_DOMID, name, config);
        } else if (domid != VMI_INVALID_DOMID) {
            ret = vmi_init_private(vmi, flags, domid, NULL, config);
        } else {
            errprint("--you need to specify either the name or the domid\n");
        }

        goto _done;

    } else {
        errprint("Custom configuration input type not defined!\n");
    }

_done:
    return ret;
}

status_t
vmi_init_complete(
    vmi_instance_t *vmi,
    char *config)
{
    uint32_t flags = VMI_INIT_COMPLETE | (*vmi)->mode;

    char *name = NULL;

    if (VMI_FILE == (*vmi)->mode) {
        name = strdup((*vmi)->image_type_complete);
    }
    else {
        name = strdup((*vmi)->image_type);
    }


    if(config) {
        flags |= VMI_CONFIG_STRING;
    } else if(name && ((*vmi)->config_mode & VMI_CONFIG_GLOBAL_FILE_ENTRY)) {
        flags |= VMI_CONFIG_GLOBAL_FILE_ENTRY;
    } else {
        flags |= VMI_CONFIG_NONE;
    }

    if (((*vmi)->flags) & VMI_INIT_EVENTS) {
        flags |= VMI_INIT_EVENTS;
    }

    vmi_destroy(*vmi);
    return vmi_init_private(vmi,
                            flags,
                            VMI_INVALID_DOMID,
                            name,
                            (vmi_config_t)config);
}

status_t
vmi_init_complete_custom(
    vmi_instance_t *vmi,
    uint32_t flags,
    vmi_config_t config)
{
    flags |= VMI_INIT_COMPLETE | (*vmi)->mode;
    vmi_destroy(*vmi);
    return vmi_init_custom(vmi, flags, config);
}

status_t
vmi_destroy(
    vmi_instance_t vmi)
{
    vmi->shutting_down = TRUE;
    if(vmi->init_mode & VMI_INIT_EVENTS){
        events_destroy(vmi);
    }
    driver_destroy(vmi);
    if (vmi->os_interface) {
        os_destroy(vmi);
    }
    if (vmi->os_data) {
        free(vmi->os_data);
    }
    vmi->os_data = NULL;
    pid_cache_destroy(vmi);
    sym_cache_destroy(vmi);
    rva_cache_destroy(vmi);
#if ENABLE_SHM_SNAPSHOT == 1
    v2m_cache_destroy(vmi);
#endif
    memory_cache_destroy(vmi);
    if (vmi->image_type)
        free(vmi->image_type);
    if (vmi)
        free(vmi);
    return VMI_SUCCESS;
}

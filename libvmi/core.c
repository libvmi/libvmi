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
read_config_file(
    vmi_instance_t vmi)
{
    status_t ret = VMI_SUCCESS;
    vmi_config_entry_t *entry;
    char *configstr = (char *)vmi->config;
    char *tmp = NULL;

    yyin = NULL;

    if (configstr) {
        yyin = fmemopen(configstr, strlen(configstr), "r");
    }

    if (NULL == yyin) {
        yyin = open_config_file();
        if (NULL == yyin) {
            fprintf(stderr, "ERROR: config file not found.\n");
            ret = VMI_FAILURE;
            goto error_exit;
        }
    }

    if (vmi_parse_config(vmi->image_type) != 0) {
        errprint("Failed to read config file.\n");
        ret = VMI_FAILURE;
        goto error_exit;
    }
    entry = vmi_get_config();

    /* copy the values from entry into instance struct */
    vmi->sysmap = strdup(entry->sysmap);
    dbprint("--got sysmap from config (%s).\n", vmi->sysmap);

    if (strncmp(entry->ostype, "Linux", CONFIG_STR_LENGTH) == 0) {
        vmi->os_type = VMI_OS_LINUX;
    }
    else if (strncmp(entry->ostype, "Windows", CONFIG_STR_LENGTH) == 0) {
        vmi->os_type = VMI_OS_WINDOWS;
    }
    else {
        errprint("Unknown or undefined OS type.\n");
        ret = VMI_FAILURE;
        goto error_exit;
    }

    /* Copy config info based on OS type */
    if (VMI_OS_LINUX == vmi->os_type) {
        dbprint("--reading in linux offsets from config file.\n");
        if (entry->offsets.linux_offsets.tasks) {
            vmi->os.linux_instance.tasks_offset =
                entry->offsets.linux_offsets.tasks;
        }

        if (entry->offsets.linux_offsets.mm) {
            vmi->os.linux_instance.mm_offset =
                entry->offsets.linux_offsets.mm;
        }

        if (entry->offsets.linux_offsets.pid) {
            vmi->os.linux_instance.pid_offset =
                entry->offsets.linux_offsets.pid;
        }

        if (entry->offsets.linux_offsets.name) {
            vmi->os.linux_instance.name_offset =
                entry->offsets.linux_offsets.name;
        }

        if (entry->offsets.linux_offsets.pgd) {
            vmi->os.linux_instance.pgd_offset =
                entry->offsets.linux_offsets.pgd;
        }
    }
    else if (VMI_OS_WINDOWS == vmi->os_type) {
        dbprint("--reading in windows offsets from config file.\n");
        if (entry->offsets.windows_offsets.ntoskrnl) {
            vmi->os.windows_instance.ntoskrnl =
                entry->offsets.windows_offsets.ntoskrnl;
        }

        if (entry->offsets.windows_offsets.tasks) {
            vmi->os.windows_instance.tasks_offset =
                entry->offsets.windows_offsets.tasks;
        }

        if (entry->offsets.windows_offsets.pdbase) {
            vmi->os.windows_instance.pdbase_offset =
                entry->offsets.windows_offsets.pdbase;
        }

        if (entry->offsets.windows_offsets.pid) {
            vmi->os.windows_instance.pid_offset =
                entry->offsets.windows_offsets.pid;
        }

        if (entry->offsets.windows_offsets.pname) {
            vmi->os.windows_instance.pname_offset =
                entry->offsets.windows_offsets.pname;
        }

        if (entry->offsets.windows_offsets.kdvb) {
            vmi->os.windows_instance.kdversion_block =
                entry->offsets.windows_offsets.kdvb;
        }

        if (entry->offsets.windows_offsets.sysproc) {
            vmi->os.windows_instance.sysproc =
                entry->offsets.windows_offsets.sysproc;
        }
    }

#ifdef VMI_DEBUG
    dbprint("--got ostype from config (%s).\n", entry->ostype);
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
    if (tmp)
        free(tmp);
    if (yyin)
        fclose(yyin);
    return ret;
}

void
read_config_ghashtable_entries(
    char* key,
    gpointer value,
    vmi_instance_t vmi)
{
    if(strncmp(key, "ostype", CONFIG_STR_LENGTH) == 0 || strncmp(key, "os_type", CONFIG_STR_LENGTH) == 0) {
        if(strncmp((char *)value, "Linux", CONFIG_STR_LENGTH) == 0) {
            vmi->os_type = VMI_OS_LINUX;
        } else if(strncmp((char *)value, "Windows", CONFIG_STR_LENGTH) == 0) {
            vmi->os_type = VMI_OS_WINDOWS;
        }
        goto _done;
    }

    if(strncmp(key, "sysmap", CONFIG_STR_LENGTH) == 0) {
        vmi->sysmap = strdup((char *)value);
        goto _done;
    }

    if (strncmp(key, "linux_tasks", CONFIG_STR_LENGTH) == 0) {
        vmi->os.linux_instance.tasks_offset =
            *(int *)value;
        goto _done;
    }

    if (strncmp(key, "linux_mm", CONFIG_STR_LENGTH) == 0) {
        vmi->os.linux_instance.mm_offset =
            *(int *)value;
        goto _done;
    }

    if (strncmp(key, "linux_pid", CONFIG_STR_LENGTH) == 0) {
        vmi->os.linux_instance.pid_offset =
            *(int *)value;
        goto _done;
    }

    if (strncmp(key, "linux_name", CONFIG_STR_LENGTH) == 0) {
        vmi->os.linux_instance.name_offset =
            *(int *)value;
        goto _done;
    }

    if (strncmp(key, "linux_pgd", CONFIG_STR_LENGTH) == 0) {
        vmi->os.linux_instance.pgd_offset =
            *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_ntoskrnl", CONFIG_STR_LENGTH) == 0) {
        vmi->os.windows_instance.ntoskrnl =
            *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_tasks", CONFIG_STR_LENGTH) == 0) {
        vmi->os.windows_instance.tasks_offset =
            *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_pdbase", CONFIG_STR_LENGTH) == 0) {
        vmi->os.windows_instance.pdbase_offset =
            *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_pid", CONFIG_STR_LENGTH) == 0) {
        vmi->os.windows_instance.pid_offset =
            *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_pname", CONFIG_STR_LENGTH) == 0) {
        vmi->os.windows_instance.pname_offset =
            *(int *)value;
        goto _done;
    }

    if (strncmp(key, "win_kdvb", CONFIG_STR_LENGTH) == 0) {
        vmi->os.windows_instance.kdversion_block =
            *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "win_sysproc", CONFIG_STR_LENGTH) == 0) {
        vmi->os.windows_instance.sysproc =
            *(addr_t *)value;
        goto _done;
    }

_done:
    return;
}

status_t
read_config_ghashtable(
    vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;
    GHashTable *configtbl = (GHashTable *)vmi->config;
    vmi->os_type = VMI_OS_UNKNOWN;

    g_hash_table_foreach(configtbl, (GHFunc)read_config_ghashtable_entries, vmi);

    if(vmi->os_type != VMI_OS_UNKNOWN) {
        ret = VMI_SUCCESS;
    } else {
        errprint("Unknown or undefined OS type!\n");
    }

    return ret;
}

static uint32_t
find_cr3(
    vmi_instance_t vmi)
{
    if (VMI_OS_WINDOWS == vmi->os_type) {
        vmi->os.windows_instance.version = VMI_OS_WINDOWS_UNKNOWN;
        return windows_find_cr3(vmi);
    }

    errprint("find_kpgd not implemented for this target OS\n");

    return 0;
}

/*
 * check that this vm uses a paging method that we support
 * and set pm/cr3/pae/pse/lme flags optionally on the given pointers
 */
status_t
get_memory_layout(
    vmi_instance_t vmi,
    page_mode_t *set_pm,
    reg_t *set_cr3,
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

    if (driver_get_vcpureg(vmi, &cr3, CR3, 0) == VMI_FAILURE) {
        errprint("**failed to get CR3\n");
        goto _exit;
    }

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
    dbprint("**set cr3 = 0x%.16"PRIx64"\n", vmi->cr3);

    /* testing to see CR3 value */
    if (!driver_is_pv(vmi) && cr3 > vmi->size) {   // sanity check on CR3
        dbprint("** Note cr3 value [0x%"PRIx64"] exceeds memsize [0x%"PRIx64"]\n",
                cr3, vmi->size);
    }

    if(set_pm != NULL) {
        *set_pm=pm;
    }
    if(set_cr3 != NULL) {
        *set_cr3=cr3;
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

    if (VMI_OS_LINUX == vmi->os_type) {
        vmi->page_offset = 0xc0000000;
    }
    else if (VMI_OS_WINDOWS == vmi->os_type) {
        vmi->page_offset = 0x80000000;
    }
    else {
        vmi->page_offset = 0;
    }
    dbprint("**set page_offset = 0x%.8x\n", vmi->page_offset);

    //TODO need a better way to handle the page size issue
    /* assume 4k pages for now, update when 4M page is found */
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
               vmi->image_type = strndup(name, 100);
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
    dbprint("LibVMI Version 0.9_alpha\n");  //TODO change this with each release

    /* save the flags and init mode */
    (*vmi)->flags = flags;
    (*vmi)->init_mode = init_mode;
    (*vmi)->config = config;
    (*vmi)->config_mode = config_mode;

    /* setup the caches */
    pid_cache_init(*vmi);
    sym_cache_init(*vmi);
    rva_cache_init(*vmi);
    v2p_cache_init(*vmi);

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

    if (init_mode & VMI_INIT_PARTIAL) {
        init_page_offset(*vmi);
        driver_get_memsize(*vmi, &(*vmi)->size);
        return VMI_SUCCESS;
    }
    else if (init_mode & VMI_INIT_COMPLETE) {

        /* init_complete requires configuration */
        if(VMI_CONFIG_NONE & (*vmi)->config_mode) {
            /* falling back to VMI_CONFIG_GLOBAL_FILE_ENTRY is unsafe here
                as the config pointer is probably NULL */
            goto error_exit;
        }
        /* read and parse the config file */
        else if ( (VMI_CONFIG_STRING & (*vmi)->config_mode || VMI_CONFIG_GLOBAL_FILE_ENTRY & (*vmi)->config_mode)
                 && VMI_FAILURE == read_config_file(*vmi)) {
            goto error_exit;
        }
        /* read and parse the ghashtable */
        else if (VMI_CONFIG_GHASHTABLE & (*vmi)->config_mode
                 && VMI_FAILURE == read_config_ghashtable(*vmi)) {
            dbprint("--failed to parse ghashtable\n");
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
        (*vmi)->pae = (*vmi)->pse = (*vmi)->lme = (*vmi)->cr3 = 0;
        (*vmi)->page_mode = VMI_PM_UNKNOWN;

        status = get_memory_layout(*vmi,
                                        &((*vmi)->page_mode),
                                        &((*vmi)->cr3),
                                        &((*vmi)->pae),
                                        &((*vmi)->pse),
                                        &((*vmi)->lme));

        if (VMI_FAILURE == status) {
            dbprint
                ("**Failed to get memory layout for VM. Trying heuristic method.\n");
            // fall-through
        }   // if

        // Heuristic method
        if (!(*vmi)->cr3) {
            (*vmi)->cr3 = find_cr3((*vmi));
            dbprint("**set cr3 = 0x%.16"PRIx64"\n", (*vmi)->cr3);
        }   // if


        /* Enable event handlers */
        if(init_mode & VMI_INIT_EVENTS){
            events_init(*vmi);
        }

        /* setup OS specific stuff */
        if (VMI_OS_LINUX == (*vmi)->os_type) {
            return linux_init(*vmi);
        }
        else if (VMI_OS_WINDOWS == (*vmi)->os_type) {
            return windows_init(*vmi);
        }
    }

error_exit:
    return status;
}

char *
build_config_str(
    vmi_instance_t *vmi,
    char *config)
{
    int length = strlen(config) + strlen((*vmi)->image_type) + 2;
    char *config_str = safe_malloc(length);

    sprintf(config_str, "%s %s\0", (*vmi)->image_type, config);
    return config_str;
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
           char *configstr = NULL;

        if (VMI_FILE == (*vmi)->mode) {
            name = strdup((*vmi)->image_type_complete);
        }
        else {
            name = strdup((*vmi)->image_type);
        }

        configstr = build_config_str(vmi, (char *)config);
        ret = vmi_init_private(vmi,flags, VMI_INVALID_DOMID, name, (vmi_config_t)configstr);

    } else if (VMI_CONFIG_GHASHTABLE == config_mode) {

        char *name = NULL;
        unsigned long domid = VMI_INVALID_DOMID;
        GHashTable *configtbl = (GHashTable *)config;

        name = (char *)g_hash_table_lookup(configtbl, "name");
        gpointer idptr;
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
    char *configstr = NULL;

    if (VMI_FILE == (*vmi)->mode) {
        name = strdup((*vmi)->image_type_complete);
    }
    else {
        name = strdup((*vmi)->image_type);
    }

    if (config) {
        configstr = build_config_str(vmi, config);
    }

    if(configstr) {
        flags |= VMI_CONFIG_STRING;
    } else if(name && (*vmi)->config_mode & VMI_CONFIG_GLOBAL_FILE_ENTRY) {
        flags |= VMI_CONFIG_GLOBAL_FILE_ENTRY;
    } else {
        flags |= VMI_CONFIG_NONE;
    }

    vmi_destroy(*vmi);
    return vmi_init_private(vmi,
                            flags,
                            VMI_INVALID_DOMID,
                            name,
                            (vmi_config_t)configstr);
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
    pid_cache_destroy(vmi);
    sym_cache_destroy(vmi);
    rva_cache_destroy(vmi);
    v2p_cache_destroy(vmi);
    memory_cache_destroy(vmi);
    if (vmi->sysmap)
        free(vmi->sysmap);
    if (vmi->image_type)
        free(vmi->image_type);
    if (vmi)
        free(vmi);
    return VMI_SUCCESS;
}

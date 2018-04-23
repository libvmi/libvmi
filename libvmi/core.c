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

#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <limits.h>
#include <fnmatch.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>

#include "private.h"
#include "driver/driver_wrapper.h"
#include "driver/memory_cache.h"
#include "os/os_interface.h"
#include "os/windows/windows.h"
#include "os/linux/linux.h"
#include "os/freebsd/freebsd.h"

#ifndef ENABLE_CONFIGFILE
static inline status_t
read_config_file(vmi_instance_t UNUSED(vmi),
                 FILE* UNUSED(config_file),
                 GHashTable** UNUSED(_config))
{
    return VMI_FAILURE;
}

static inline status_t
read_config_string(vmi_instance_t UNUSED(vmi),
                   const char* UNUSED(config),
                   GHashTable** UNUSED(_config),
                   vmi_init_error_t* UNUSED(error))
{
    return VMI_FAILURE;
}

static inline status_t
read_config_file_entry(vmi_instance_t UNUSED(vmi),
                       GHashTable** UNUSED(config),
                       vmi_init_error_t* UNUSED(error))
{
    return VMI_FAILURE;
}
#else

#include "config/config_parser.h"

extern FILE *yyin;

static FILE *
open_config_file(
)
{
    FILE *f = NULL;
    char *location;
    char *sudo_user = NULL;
    struct passwd *pw_entry = NULL;
    char cwd[1024] = { 0 };

    /* check current directory */
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        location = g_malloc0(snprintf(NULL,0,"%s/libvmi.conf", cwd)+1);
        if ( !location )
            return NULL;

        sprintf(location, "%s/libvmi.conf", cwd);
        dbprint(VMI_DEBUG_CORE, "--looking for config file at %s\n", location);

        f = fopen(location, "r");

        if (f) {
            goto success;
        }
        g_free(location);
    }

    /* next check home directory of sudo user */
    if ((sudo_user = getenv("SUDO_USER")) != NULL) {
        if ((pw_entry = getpwnam(sudo_user)) != NULL) {
            location = g_malloc0(snprintf(NULL,0,"%s/etc/libvmi.conf", pw_entry->pw_dir)+1);
            if ( !location )
                return NULL;

            sprintf(location, "%s/etc/libvmi.conf",
                    pw_entry->pw_dir);
            dbprint(VMI_DEBUG_CORE, "--looking for config file at %s\n", location);

            f = fopen(location, "r");

            if (f) {
                goto success;
            }
            g_free(location);
        }
    }

    /* next check home directory for current user */
    location = g_malloc0(snprintf(NULL,0,"%s/etc/libvmi.conf", getenv("HOME"))+1);
    if ( !location )
        return NULL;

    sprintf(location, "%s/etc/libvmi.conf", getenv("HOME"));
    dbprint(VMI_DEBUG_CORE, "--looking for config file at %s\n", location);

    f = fopen(location, "r");

    if (f) {
        goto success;
    }
    g_free(location);

    /* finally check in /etc */
    dbprint(VMI_DEBUG_CORE, "--looking for config file at /etc/libvmi.conf\n");
    location = g_malloc0(strlen("/etc/libvmi.conf")+1);
    if ( !location )
        return NULL;

    sprintf(location, "/etc/libvmi.conf");
    f = fopen(location, "r");
    if (f) {
        goto success;
    }
    g_free(location);

    return NULL;
success:
    dbprint(VMI_DEBUG_CORE, "**Using config file at %s\n", location);
    free(location);
    return f;
}

static status_t
read_config_file(vmi_instance_t vmi, FILE* config_file,
                 GHashTable **config, vmi_init_error_t *error)
{
    status_t ret = VMI_FAILURE;

    yyin = config_file;

    if (vmi_parse_config(vmi->image_type) != 0) {
        if ( error )
            *error = VMI_INIT_ERROR_NO_CONFIG;

        errprint("Failed to read config file.\n");
        goto error_exit;
    }

    *config = vmi_get_config();

    if (*config == NULL) {
        if ( error )
            *error = VMI_INIT_ERROR_NO_CONFIG_ENTRY;

        errprint("No entry in config file for %s.\n", vmi->image_type);
        goto error_exit;
    }

    ret = VMI_SUCCESS;

error_exit:
    if (config_file)
        fclose(config_file);

    return ret;
}

status_t read_config_string(vmi_instance_t vmi,
                            const char *config,
                            GHashTable **_config,
                            vmi_init_error_t *error)
{
    status_t ret = VMI_SUCCESS;
    FILE* config_file = NULL;

    if (config == NULL) {
        if ( error )
            *error = VMI_INIT_ERROR_NO_CONFIG;

        errprint("VMI_ERROR: NULL string passed for VMI_CONFIG_STRING\n");
        return VMI_FAILURE;
    }

    int length = snprintf(NULL, 0, "%s %s", vmi->image_type, config) + 1;
    char *config_str = g_malloc0(length);

    sprintf(config_str, "%s %s", vmi->image_type, config);

    config_file = fmemopen(config_str, length, "r");
    ret = read_config_file(vmi, config_file, _config, error);

    free(config_str);

    return ret;
}

static status_t
read_config_file_entry(vmi_instance_t vmi, GHashTable **config, vmi_init_error_t *error)
{
    FILE* config_file = open_config_file();
    if (NULL == config_file) {
        if ( error )
            *error = VMI_INIT_ERROR_NO_CONFIG;

        fprintf(stderr, "ERROR: config file not found.\n");
        return VMI_FAILURE;
    }

    return read_config_file(vmi, config_file, config, error);
}

#endif

status_t
set_os_type_from_config(
    vmi_instance_t vmi,
    GHashTable *configtbl)
{
    status_t ret = VMI_FAILURE;
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

    if (!strcmp(ostype, "Linux")) {
        vmi->os_type = VMI_OS_LINUX;
        ret = VMI_SUCCESS;
    } else if (!strcmp(ostype, "Windows")) {
        vmi->os_type = VMI_OS_WINDOWS;
        ret = VMI_SUCCESS;
    } else if (!strcmp(ostype, "FreeBSD")) {
        vmi->os_type = VMI_OS_FREEBSD;
        ret = VMI_SUCCESS;
    } else {
        errprint("VMI_ERROR: Unknown OS type: %s!\n", ostype);
        ret = VMI_FAILURE;
    }

#ifdef VMI_DEBUG
    if (vmi->os_type == VMI_OS_LINUX) {
        dbprint(VMI_DEBUG_CORE, "**set os_type to Linux.\n");
    } else if (vmi->os_type == VMI_OS_WINDOWS) {
        dbprint(VMI_DEBUG_CORE, "**set os_type to Windows.\n");
    }     else if (vmi->os_type == VMI_OS_FREEBSD) {
        dbprint(VMI_DEBUG_CORE, "**set os_type to FreeBSD.\n");
    } else {
        dbprint(VMI_DEBUG_CORE, "**set os_type to unknown.\n");
    }
#endif

    return ret;
}

static inline status_t
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

/* the name passed may contain the full path and we just want the filename */
static inline void
set_image_type_for_file(
    vmi_instance_t vmi,
    const char *name)
{
    const char *ptr = NULL;

    if ((ptr = strrchr(name, '/')) == NULL) {
        ptr = name;
    } else {
        ptr++;
    }
    vmi->image_type = strndup(ptr, 500);
    vmi->image_type_complete = strndup(name, 500);
}

static status_t
set_id_and_name(
    vmi_instance_t vmi,
    void *domain)
{
    const char *name = NULL;
    uint64_t id = 0;

    if ( vmi->init_flags & VMI_INIT_DOMAINNAME )
        name = (const char*) domain;
    if ( vmi->init_flags & VMI_INIT_DOMAINID )
        id = *(uint64_t*) domain;

    if ( name && id ) {
        errprint("Specifying both name and id is not valid!\n");
        return VMI_FAILURE;
    }

    if ( !name && !id ) {
        errprint("Specifying either name or id is required!\n");
        return VMI_FAILURE;
    }

    if (VMI_FILE == vmi->mode) {
        if (name) {
            set_image_type_for_file(vmi, name);
            driver_set_name(vmi, name);
            goto done;
        }

        errprint("Must specify name for file mode.\n");
        return VMI_FAILURE;
    }

    /* resolve and set id from name */
    if (name) {
        if (VMI_INVALID_DOMID != (id = driver_get_id_from_name(vmi, name)) ) {
            dbprint(VMI_DEBUG_CORE, "--got id from name (%s --> %"PRIu64")\n", name, id);
            driver_set_id(vmi, id);
            vmi->image_type = strndup(name, 100);
            if ( vmi->image_type ) {
                driver_set_name(vmi, name);
                goto done;
            }
        }

        errprint("Failed to get domain id from name.\n");
        return VMI_FAILURE;
    }

    /* resolve and set name from id */
    if (VMI_FAILURE == driver_check_id(vmi,id)) {
        errprint("Invalid id.\n");
        return VMI_FAILURE;
    }

    driver_set_id(vmi, id);

    char *tmp_name = NULL;
    if (VMI_SUCCESS == driver_get_name_from_id(vmi, id, &tmp_name) && tmp_name) {
        dbprint(VMI_DEBUG_CORE, "--got name from id (%"PRIu64" --> %s)\n", id, tmp_name);
        vmi->image_type = strndup(tmp_name, 100);
        if ( vmi->image_type ) {
            driver_set_name(vmi, tmp_name);
            free(tmp_name);
            goto done;
        }
    }

    dbprint(VMI_DEBUG_CORE, "--failed to get domain name from id!\n");

#if !defined(HAVE_XS_H) && !defined(HAVE_XENSTORE_H)
    // Only under Xen this is OK without Xenstore
    if (vmi->mode == VMI_XEN) {
        // create placeholder for image_type
        char *idstring = g_malloc0(snprintf(NULL, 0, "domid-%"PRIu64, id) + 1);
        if ( idstring ) {
            sprintf(idstring, "domid-%"PRIu64, id);
            vmi->image_type = idstring;
            goto done;
        }
    }
#endif

    return VMI_FAILURE;

done:
    dbprint(VMI_DEBUG_CORE, "**set image_type = %s\n", vmi->image_type);
    return VMI_SUCCESS;
}

page_mode_t
vmi_get_page_mode(
    vmi_instance_t vmi,
    unsigned long vcpu)
{
    page_mode_t pm = VMI_PM_UNKNOWN;

    if ( !vmi )
        return pm;

    if ( VMI_FILE == vmi->mode )
        return vmi->page_mode;

    if (VMI_SUCCESS == find_page_mode_live(vmi, vcpu, &pm) ) {
        if ( vcpu == 0 && vmi->page_mode != pm )
            dbprint(VMI_DEBUG_CORE,
                    "The page-mode we just identified doesn't match what LibVMI previously recorded! "
                    "You should re-run vmi_init_paging.\n");
    }

    return pm;
}

status_t
vmi_get_access_mode(
    vmi_instance_t vmi,
    void *domain,
    uint64_t init_flags,
    void* init_data,
    vmi_mode_t *mode)
{
    if ( vmi ) {
        *mode = vmi->mode;
        return VMI_SUCCESS;
    }

    const char *name = NULL;
    uint64_t id = VMI_INVALID_DOMID;

    if ( init_flags & VMI_INIT_DOMAINNAME )
        name = (const char *)domain;
    if ( init_flags & VMI_INIT_DOMAINID )
        id = *(uint64_t*)domain;

    if ( (!name && id == VMI_INIT_DOMAINID) ||
            (name && id != VMI_INVALID_DOMID) )
        return VMI_FAILURE;

    return driver_init_mode(name, id, init_flags, init_data, mode);
}

static inline status_t driver_sanity_check(vmi_mode_t mode)
{
    switch ( mode ) {
        case VMI_XEN:
#if ENABLE_XEN != 1
            return VMI_FAILURE;
#endif
            break;
        case VMI_KVM:
#if ENABLE_KVM != 1
            return VMI_FAILURE;
#endif
            break;
        case VMI_FILE:
#if ENABLE_FILE != 1
            return VMI_FAILURE;
#endif
            break;
        default:
            return VMI_FAILURE;
    };

    return VMI_SUCCESS;
}

status_t vmi_init(
    vmi_instance_t *vmi,
    vmi_mode_t mode,
    void* domain,
    uint64_t init_flags,
    void *init_data,
    vmi_init_error_t *error)
{
    if ( VMI_FAILURE == driver_sanity_check(mode) ) {
        errprint("The selected LibVMI mode is not available!\n");
        return VMI_FAILURE;
    }

    status_t status = VMI_FAILURE;

    /* allocate memory for instance structure */
    vmi_instance_t _vmi = (vmi_instance_t) g_malloc0(sizeof(struct vmi_instance));
    if ( !_vmi )
        return VMI_FAILURE;

    /* initialize instance struct to default values */
    dbprint(VMI_DEBUG_CORE, "LibVMI Version %s\n", PACKAGE_VERSION);

    _vmi->mode = mode;
    dbprint(VMI_DEBUG_CORE, "LibVMI Driver Mode %d\n", _vmi->mode);

    _vmi->init_flags = init_flags;

    /* driver-specific initilization */
    if (VMI_FAILURE == driver_init(_vmi, init_flags, init_data)) {
        if ( error )
            *error = VMI_INIT_ERROR_DRIVER;

        goto error_exit;
    }
    dbprint(VMI_DEBUG_CORE, "--completed driver init.\n");

    /* setup the page offset size */
    if (VMI_FAILURE == init_page_offset(_vmi)) {
        if ( error )
            *error = VMI_INIT_ERROR_DRIVER;

        goto error_exit;
    }

    /* resolve the id and name */
    if (VMI_FAILURE == set_id_and_name(_vmi, domain)) {
        if ( error )
            *error = VMI_INIT_ERROR_VM_NOT_FOUND;

        goto error_exit;
    }

    /* init vmi for specific file/domain through the driver */
    if (VMI_FAILURE == driver_init_vmi(_vmi, init_flags, init_data)) {
        if ( error )
            *error = VMI_INIT_ERROR_DRIVER;

        goto error_exit;
    }

    /* get the memory size */
    if (driver_get_memsize(_vmi, &_vmi->allocated_ram_size, &_vmi->max_physical_address) == VMI_FAILURE) {
        if ( error )
            *error = VMI_INIT_ERROR_DRIVER;

        goto error_exit;
    }

    /* setup the caches */
    pid_cache_init(_vmi);
    sym_cache_init(_vmi);
    rva_cache_init(_vmi);
    v2p_cache_init(_vmi);

    status = VMI_SUCCESS;

    dbprint(VMI_DEBUG_CORE, "**set allocated_ram_size = %"PRIx64", "
            "max_physical_address = 0x%"PRIx64"\n",
            _vmi->allocated_ram_size,
            _vmi->max_physical_address);

    if ( init_flags & VMI_INIT_SHM ) {
#if ENABLE_SHM_SNAPSHOT == 1
        v2m_cache_init(_vmi);
#else
        if ( error )
            *error = VMI_INIT_ERROR_SHM;

        errprint("LibVMI wasn't compiled with SHM support!\n");
        goto error_exit;
#endif
    }

    if ( init_flags & VMI_INIT_EVENTS ) {
        status = events_init(_vmi);
        if ( error && VMI_FAILURE == status )
            *error = VMI_INIT_ERROR_EVENTS;
    }

error_exit:
    if ( VMI_FAILURE == status ) {
        vmi_destroy(_vmi);
        *vmi = NULL;
    } else
        *vmi = _vmi;

    return status;
}

page_mode_t vmi_init_paging(
    vmi_instance_t vmi,
    uint64_t flags)
{
    if ( !vmi )
        return VMI_PM_UNKNOWN;

    vmi->page_mode = VMI_PM_UNKNOWN;

    if ( VMI_FAILURE == arch_init(vmi) )
        return VMI_PM_UNKNOWN;

    if ( flags ) {
        switch (vmi->page_mode) {
            case VMI_PM_LEGACY:
            case VMI_PM_PAE:
            case VMI_PM_IA32E:
                if (flags & VMI_PM_INITFLAG_TRANSITION_PAGES)
                    vmi->x86.transition_pages = true;
                break;
            default:
                break;
        };
    }

    return vmi->page_mode;
}

os_t vmi_init_os(
    vmi_instance_t vmi,
    vmi_config_t config_mode,
    void *config,
    vmi_init_error_t *error)
{
    if (!vmi)
        return VMI_OS_UNKNOWN;

    vmi->os_type = VMI_OS_UNKNOWN;
    GHashTable *_config = NULL;

    switch (config_mode) {
        case VMI_CONFIG_STRING:
            /* read and parse the config string */
            if (VMI_FAILURE == read_config_string(vmi, (const char*)config, &_config, error)) {
                goto error_exit;
            }
            break;
        case VMI_CONFIG_GLOBAL_FILE_ENTRY:
            /* read and parse the config file */
            if (VMI_FAILURE == read_config_file_entry(vmi, &_config, error)) {
                goto error_exit;
            }
            break;
        case VMI_CONFIG_GHASHTABLE:
            /* read and parse the ghashtable */
            if (!config) {

                if (error)
                    *error = VMI_INIT_ERROR_NO_CONFIG;

                goto error_exit;
            }
            _config = (GHashTable*)config;
            break;
        default:
            goto error_exit;
    }

    if (VMI_FAILURE == set_os_type_from_config(vmi, _config)) {
        if ( error )
            *error = VMI_INIT_ERROR_NO_CONFIG_ENTRY;

        dbprint(VMI_DEBUG_CORE, "--failed to determine os type from config\n");
        goto error_exit;
    }

    /*
     * Initialize paging if it hasn't been done yet. For VMI_FILE mode it
     * will be called from the OS init function as it requires OS-specific
     * heuristics.
     */
    if ( VMI_FILE != vmi->mode && VMI_PM_UNKNOWN == vmi->page_mode &&
            VMI_PM_UNKNOWN == vmi_init_paging(vmi, 0) ) {
        vmi->os_type = VMI_OS_UNKNOWN;
        if ( error )
            *error = VMI_INIT_ERROR_PAGING;

        goto error_exit;
    }

    /* setup OS specific stuff */
    switch ( vmi->os_type ) {
#ifdef ENABLE_LINUX
        case VMI_OS_LINUX:
            if (VMI_FAILURE == linux_init(vmi, _config)) {
                vmi->os_type = VMI_OS_UNKNOWN;
                if ( error )
                    *error = VMI_INIT_ERROR_OS;

                goto error_exit;
            }
            break;
#endif
#ifdef ENABLE_WINDOWS
        case VMI_OS_WINDOWS:
            if (VMI_FAILURE == windows_init(vmi, _config)) {
                vmi->os_type = VMI_OS_UNKNOWN;
                if ( error )
                    *error = VMI_INIT_ERROR_OS;

                goto error_exit;
            }
            break;
#endif
#ifdef ENABLE_FREEBSD
        case VMI_OS_FREEBSD:
            if (VMI_FAILURE == freebsd_init(vmi, _config)) {
                vmi->os_type = VMI_OS_UNKNOWN;
                if ( error )
                    *error = VMI_INIT_ERROR_OS;

                goto error_exit;
            }
            break;
#endif
        default:
            vmi->os_type = VMI_OS_UNKNOWN;
            if ( error )
                *error = VMI_INIT_ERROR_OS;

            goto error_exit;
    };

error_exit:
    return vmi->os_type;
}

status_t
vmi_init_complete(
    vmi_instance_t *vmi,
    void *domain,
    uint64_t init_flags,
    void *init_data,
    vmi_config_t config_mode,
    void *config,
    vmi_init_error_t *error)
{
    vmi_instance_t _vmi = NULL;
    vmi_mode_t mode;

    if ( VMI_FAILURE == vmi_get_access_mode(_vmi, domain, init_flags, init_data, &mode) ) {
        if ( error )
            *error = VMI_INIT_ERROR_DRIVER_NOT_DETECTED;

        return VMI_FAILURE;
    }

    if ( VMI_FAILURE == vmi_init(&_vmi, mode, domain, init_flags, init_data, error) )
        return VMI_FAILURE;

    /*
     * For file-mode initialization OS specific heuristics are required,
     * which are being called in vmi_init_os.
     */
    if ( VMI_FILE != mode && VMI_PM_UNKNOWN == vmi_init_paging(_vmi, 0) ) {
        if ( error )
            *error = VMI_INIT_ERROR_PAGING;

        return VMI_FAILURE;
    }

    if ( VMI_OS_UNKNOWN == vmi_init_os(_vmi, config_mode, config, error) )
        return VMI_FAILURE;

    *vmi = _vmi;
    return VMI_SUCCESS;
}

status_t
vmi_destroy(
    vmi_instance_t vmi)
{
    if (!vmi)
        return VMI_FAILURE;

    vmi->shutting_down = TRUE;
    driver_destroy(vmi);
    events_destroy(vmi);
    if (vmi->os_interface) {
        os_destroy(vmi);
    }
    if (vmi->os_data) {
        free(vmi->os_data);
    }
    if (vmi->arch_interface) {
        free(vmi->arch_interface);
    }
    vmi->os_data = NULL;
    pid_cache_destroy(vmi);
    sym_cache_destroy(vmi);
    rva_cache_destroy(vmi);
    v2p_cache_destroy(vmi);

#if ENABLE_SHM_SNAPSHOT == 1
    v2m_cache_destroy(vmi);
#endif

    memory_cache_destroy(vmi);
    if (vmi->image_type)
        free(vmi->image_type);
    free(vmi);
    return VMI_SUCCESS;
}

vmi_arch_t
vmi_get_library_arch()
{
#ifdef I386
    return VMI_ARCH_X86;
#elif X86_64
    return VMI_ARCH_X86_64;
#elif ARM32
    return VMI_ARCH_ARM32;
#elif ARM64
    return VMI_ARCH_ARM64;
#endif

    return VMI_ARCH_UNKNOWN;
}

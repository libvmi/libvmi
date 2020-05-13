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
 * @file libvmi_extra.h
 * @brief The Extra LibVMI API is defined here.
 *
 * To use GLib functions compile with -DLIBVMI_EXTRA_GLIB
 * To use JSON functions compile with -DLIBVMI_EXTRA_JSON
 */
#ifndef LIBVMI_EXTRA_H
#define LIBVMI_EXTRA_H

#ifdef __cplusplus
extern "C" {
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#pragma GCC visibility push(default)

#ifdef LIBVMI_EXTRA_GLIB
#include <glib.h>

/**
 * Retrieve the pages mapped into the address space of a process.
 * @param[in] vmi Instance
 * @param[in] dtb The directory table base of the process
 *
 * @return GSList of page_info_t structures, or NULL on error.
 * The caller is responsible for freeing the list and the structs.
 */
GSList* vmi_get_va_pages(
    vmi_instance_t vmi,
    addr_t dtb) NOEXCEPT;
#endif

#ifdef LIBVMI_EXTRA_JSON
#include <json-c/json.h>

/**
 * Initialize kernel's JSON profile from particular config type.
 * After this operation, it will be possible to use JSON-related functions,
 * like vmi_get_kernel_json or vmi_get_struct_member_offset_from_json.
 * However, it will be not possible to perform functions that interact
 * with the physical memory unless paging is initialized.
 * Moreover, to use functions that interact with the virual memory,
 * it is also necessary to perform vmi_init_os.
 * @param[in] vmi Instance
 * @param[in] config_mode The type of OS configuration that is provided.
 * @param[in] config Configuration is passed directly to LibVMI (ie. in a string
 *                   or in a GHashTable) or NULL of global config file is used.
 * @return os_t Type of the initialized OS, according to the provided config.
 *              VMI_OS_UNKNOWN is returned on failure.
 */
os_t vmi_init_profile(
    vmi_instance_t vmi,
    vmi_config_t config_mode,
    void *config) NOEXCEPT;

/**
 * Retrieve the kernel's open json_object
 * @param[in] vmi Instance
 *
 * @return The json_object* open for the VM or NULL on error.
 */
json_object* vmi_get_kernel_json(
    vmi_instance_t vmi) NOEXCEPT;

/**
 * Look up the provided symbol's address from the json
 * @param[in] vmi Instance
 * @param[in] json The open json_object* to use
 * @param[in] symbol The symbol to look up
 * @param[out] addr The symbol's address
 *
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_get_symbol_addr_from_json(
    vmi_instance_t vmi,
    json_object* json,
    const char* symbol,
    addr_t* addr) NOEXCEPT;

/**
 * Look up the provided structure's size from the json
 * @param[in] vmi Instance
 * @param[in] json The open json_object* to use
 * @param[in] struct_name The structure's name to look up
 * @param[out] size The structure's size
 *
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_get_struct_size_from_json(
    vmi_instance_t vmi,
    json_object* json,
    const char* struct_name,
    size_t* size) NOEXCEPT;

/**
 * Look up the provided symbol's address from the json
 * @param[in] vmi Instance
 * @param[in] json The open json_object* to use
 * @param[in] struct_name The structure's name
 * @param[in] struct_member The structure's member
 * @param[out] offset The structure member's offset
 *
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_get_struct_member_offset_from_json(
    vmi_instance_t vmi,
    json_object* json,
    const char* struct_name,
    const char* struct_member,
    addr_t* offset) NOEXCEPT;

/**
 * Look up the provided symbol's address and bit position from the json
 * @param[in] vmi Instance
 * @param[in] json The open json_object* to use
 * @param[in] struct_name The structure's name
 * @param[in] struct_member The structure's member
 * @param[out] offset The structure member's offset
 * @param[out] start_bit The structure member's start bit offset
 * @param[out] end_bit The structure member's end bit offset
 *
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_get_bitfield_offset_and_size_from_json(vmi_instance_t vmi, json_object *json,
        const char *struct_name,
        const char *struct_member,
        addr_t *offset, size_t *start_bit,
        size_t *end_bit);
#endif

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif /* LIBVMI_EXTRA_H */

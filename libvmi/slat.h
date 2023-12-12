/* The LibVMI Library is an introspection library that simplifies access to
* memory in a target virtual machine or in a file containing a dump of
* a system's physical memory.  LibVMI is based on the XenAccess Library.
*
* Author: Kevin Mayer (kevin.mayer@gdata.de)
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
* @file slat.h
* @brief The LibVMI second level address translation API is defined here.
*
* The SLAT (Second Level Address Translation) is used to circumvent the
* overhead of shadow page tables. By modifying the pointer to the
* translation tables they can also be used to switch between completely
* different sets of access rights for memory pages.
*/

#ifndef LIBVMI_SLAT_H
#define LIBVMI_SLAT_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#pragma GCC visibility push(default)

/**
* Checks if slat is enabled on the domain
*
* @deprecated This function is deprecated in favor of
* vmi_slat_state and will be removed soon.
*
* @param[in] vmi LibVMI instance
* @param[out] state slat state of the domain
* @return VMI_SUCCESS or VMI_FAILURE
*/
__attribute__((deprecated))
status_t vmi_slat_get_domain_state (
    vmi_instance_t vmi,
    bool *state) NOEXCEPT;

/**
* Checks if SLAT is enabled for the current VM.
*
* @param[in] vmi LibVMI instance
* @param[out] state SLAT state
* @return VMI_SUCCESS or VMI_FAILURE
*/
status_t vmi_slat_state (
    vmi_instance_t vmi,
    bool *state) NOEXCEPT;

/**
* Enables or disables slat for the domain
*
* @deprecated This function is deprecated in favor of
* vmi_slat_control and will be removed soon.
*
* @param[in] vmi LibVMI instance
* @param[in] state slat state of the domain
* @return VMI_SUCCESS or VMI_FAILURE
*/
__attribute__((deprecated))
status_t vmi_slat_set_domain_state (
    vmi_instance_t vmi,
    bool state) NOEXCEPT;

/**
* Enables or disables SLAT for the current VM.
*
* @param[in] vmi LibVMI instance
* @param[in] state SLAT state of the domain
* @return VMI_SUCCESS or VMI_FAILURE
*/
status_t vmi_slat_control (
    vmi_instance_t vmi,
    bool state) NOEXCEPT;

/**
* Creates a new SLAT view.
*
* @param[in] vmi LibVMI instance
* @param[out] slat_id ID of the newly created view
* @return VMI_SUCCESS or VMI_FAILURE
*/
status_t vmi_slat_create (
    vmi_instance_t vmi,
    uint16_t *slat_id) NOEXCEPT;

/**
* Destroys a SLAT view.
*
* @param[in] vmi LibVMI instance
* @param[in] slat_id ID of the view to destroy
* @return VMI_SUCCESS or VMI_FAILURE
*/
status_t vmi_slat_destroy (
    vmi_instance_t vmi,
    uint16_t slat_idx) NOEXCEPT;

/**
* Switches to a specific SLAT view.
*
* @param[in] vmi LibVMI instance
* @param[in] slat_id ID of the view to switch to
* @return VMI_SUCCESS or VMI_FAILURE
*/
status_t vmi_slat_switch (
    vmi_instance_t vmi,
    uint16_t slat_idx) NOEXCEPT;

/**
* Changes the virtual to physical memory mapping for a page in a specific view.
* The change is transparent for the guest.
*
* @param[in] vmi LibVMI instance
* @param[in] slat_id ID of the view in which to apply the change
* @param[in] old_gfn The old gfn
* @param[in] new_gfn The new gfn
* @return VMI_SUCCESS or VMI_FAILURE
*/
status_t vmi_slat_change_gfn (
    vmi_instance_t vmi,
    uint16_t slat_idx,
    addr_t old_gfn,
    addr_t new_gfn) NOEXCEPT;

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif /* LIBVMI_SLAT_H */

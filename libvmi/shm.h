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
 * @file shm.h
 * @brief The LibVMI SHM API is defined here.
 *
 * More detailed description can go here.
 */
#ifndef LIBVMI_SHM_H
#define LIBVMI_SHM_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

/**
 * Create a shm-snapshot and enter "shm-snapshot" mode.
 *  (KVM only, Xen support is pending.)
 *  (This API requires a patch to KVM.)
 * If LibVMI is in "live" mode (i.e. KVM patch or KVM native), this will
 * switch it to "shm-snapshot" mode; If LibVMI is already in "shm-snapshot" mode,
 * this will destroy the old shm-snapshot and create a new one.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_shm_snapshot_create(
    vmi_instance_t vmi);

/**
 * Destroy existed shm-snapshot and exit "shm-snapshot" mode.
 *  (KVM only, Xen support is pending.)
 *  (This API requires a patch to KVM.)
 * If LibVMI is in "shm-snapshot", this API will switch it to "live" mode
 * (i.e. KVM patch or KVM native); if LibVMI is already in "live" mode,
 * this API does nothing.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_shm_snapshot_destroy(
    vmi_instance_t vmi);

/**
 * Direct Guest Physical Memory Access:  A similar memory read semantic to
 *  vmi_read_pa() but a non-copy direct access.
 * Note that it is only capable for shm-snapshot.
 * @param[in] vmi LibVMI instance
 * @param[in] paddr
 * @param[out] medial_addr_ptr
 * @param[in] count the expected count of bytes
 * @return the actual count that less or equal than count[in]
 */
size_t vmi_get_dgpma(
    vmi_instance_t vmi,
    addr_t paddr,
    void **buf_ptr,
    size_t count);

/**
 * Direct Guest Virtual Memory Access:  A similar memory read semantic to
 *  vmi_read_pa() but a non-copy direct access.
 * Note that it is only capable for shm-snapshot.
 * @param[in] vmi LibVMI instance
 * @param[in] vaddr
 * @param[in] pid
 * @param[out] medial_addr_ptr
 * @param[in] count the expected count of bytes
 * @return the actual count that less or equal than count[in]
 */
size_t vmi_get_dgvma(
    vmi_instance_t vmi,
    addr_t vaddr,
    pid_t pid,
    void **buf_ptr,
    size_t count);

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif /* LIBVMI_SHM_H */

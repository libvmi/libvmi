/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
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

#ifndef KVM_PRIVATE_H
#define KVM_PRIVATE_H

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

#include "private.h"
#include "libvirt_wrapper.h"

#if ENABLE_SHM_SNAPSHOT == 1
#include "driver/kvm/kvm_shm.h"
#endif

typedef struct kvm_instance {
    virConnectPtr conn;
    virDomainPtr dom;
    uint32_t id;
    char *name;
    char *ds_path;
    int socket_fd;
    libvirt_wrapper_t libvirt;
#if ENABLE_SHM_SNAPSHOT == 1
    char *shm_snapshot_path;  /** shared memory snapshot device path in /dev/shm directory */
    int   shm_snapshot_fd;    /** file description of the shared memory snapshot device */
    void *shm_snapshot_map;   /** mapped shared memory region */
    char *shm_snapshot_cpu_regs;  /** string of dumped CPU registers */
    v2m_table_t shm_snapshot_v2m_tables; /** V2m tables of all pids */
#endif /* ENABLE_SHM_SNAPSHOT */
} kvm_instance_t;

static inline kvm_instance_t *
kvm_get_instance(
    vmi_instance_t vmi)
{
    return ((kvm_instance_t *) vmi->driver.driver_data);
}

#endif

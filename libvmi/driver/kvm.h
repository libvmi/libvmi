/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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

#if ENABLE_KVM == 1
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

typedef struct kvm_instance{
    virConnectPtr conn;
    virDomainPtr dom;
    unsigned long id;
    char *name;
    char *ds_path;
    int socket_fd;
} kvm_instance_t;

#else

typedef struct kvm_instance{
} kvm_instance_t;

#endif /* ENABLE_KVM */

status_t kvm_init (vmi_instance_t vmi);
void kvm_destroy (vmi_instance_t vmi);
unsigned long kvm_get_id_from_name (vmi_instance_t vmi, char *name);
unsigned long kvm_get_id (vmi_instance_t vmi);
void kvm_set_id (vmi_instance_t vmi, unsigned long id);
status_t kvm_get_name (vmi_instance_t vmi, char **name);
void kvm_set_name (vmi_instance_t vmi, char *name);
status_t kvm_get_memsize (vmi_instance_t vmi, unsigned long *size);
status_t kvm_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu);
addr_t kvm_pfn_to_mfn (vmi_instance_t vmi, addr_t pfn);
void *kvm_read_page (vmi_instance_t vmi, addr_t page);
status_t kvm_write (vmi_instance_t vmi, addr_t paddr, void *buf, uint32_t length);
int kvm_is_pv (vmi_instance_t vmi);
status_t kvm_test (unsigned long id, char *name);
status_t kvm_pause_vm (vmi_instance_t vmi);
status_t kvm_resume_vm (vmi_instance_t vmi);

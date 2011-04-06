/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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
unsigned long kvm_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn);
void *kvm_map_page (vmi_instance_t vmi, int prot, unsigned long page);
int kvm_is_pv (vmi_instance_t vmi);
status_t kvm_test (unsigned long id, char *name);
status_t kvm_pause_vm (vmi_instance_t vmi);
status_t kvm_resume_vm (vmi_instance_t vmi);

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
#include "driver/kvm.h"
#include "driver/interface.h"

#if ENABLE_KVM == 1
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

// request struct matches a definition in qemu source code
struct request{
    uint8_t type;  // 0 quit, 1 read, ... rest reserved
    uint64_t address;
    uint64_t length;
};

//----------------------------------------------------------------------------
// Helper functions

//
// QMP Command Interactions
static char *exec_qmp_cmd (kvm_instance_t *kvm, char *query)
{
    FILE *p;
    int status;
    char *output = safe_malloc(4096);
    size_t length = 0;

    char *name = (char *) virDomainGetName(kvm->dom);
    int cmd_length = strlen(name) + strlen(query) + 29;
    char *cmd = safe_malloc(cmd_length);
    snprintf(cmd, cmd_length, "virsh qemu-monitor-command %s %s", name, query);
    
    p = popen(cmd, "r");
    if (NULL == p){
        dbprint("--failed to run QMP command\n");
        return NULL;
    }

    length = fread(output, 1, 4096, p);
    pclose(p);
    
    if (length == 0){
        free(output);
        return NULL;
    }
    else{
        return output;
    }
}

static char *exec_info_registers (kvm_instance_t *kvm)
{
    char *query = "'{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"info registers\"}}'";
    return exec_qmp_cmd(kvm, query);
}

static char *exec_memory_access (kvm_instance_t *kvm)
{
    char *tmpfile = tempnam("/tmp", "vmi");
    char *query = (char *) malloc(256);
    sprintf(query, "'{\"execute\": \"pmemaccess\", \"arguments\": {\"path\": \"%s\"}}'", tmpfile);
    kvm->ds_path = strdup(tmpfile);
    free(tmpfile);
    return exec_qmp_cmd(kvm, query);
}

static reg_t parse_reg_value (char *regname, char *ir_output)
{
    char *ptr = strcasestr(ir_output, regname);
    if (NULL != ptr){
        ptr += strlen(regname) + 1;
        return (reg_t) strtoll(ptr, (char **) NULL, 16);
    }
    else{
        return 0;
    }
}

//
// Domain socket interactions (for memory access from KVM-QEMU)
static status_t init_domain_socket (kvm_instance_t *kvm)
{
    struct sockaddr_un address;
    int socket_fd;
    size_t address_length;

    socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(socket_fd < 0){
        dbprint("--socket() failed\n");
        return VMI_FAILURE;
    }

    address.sun_family = AF_UNIX;
    address_length = sizeof(address.sun_family) + sprintf(address.sun_path, "%s", kvm->ds_path);

    if(connect(socket_fd, (struct sockaddr *) &address, address_length) != 0){
        dbprint("--connect() failed to %s\n", kvm->ds_path);
        return VMI_FAILURE;
    }

    kvm->socket_fd = socket_fd;
    return VMI_SUCCESS;
}

static void destroy_domain_socket (kvm_instance_t *kvm)
{
    struct request req;
    req.type = 0; // quit
    req.address = 0;
    req.length = 0;
    write(kvm->socket_fd, &req, sizeof(struct request));
}

//----------------------------------------------------------------------------
// KVM-Specific Interface Functions (no direction mapping to driver_*)

static kvm_instance_t *kvm_get_instance (vmi_instance_t vmi)
{
    return ((kvm_instance_t *) vmi->driver);
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t kvm_init (vmi_instance_t vmi)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;

    conn = virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault, 0);
    if (NULL == conn){
        dbprint("--no connection to kvm hypervisor\n");
        return VMI_FAILURE;
    }

    dom = virDomainLookupByID(conn, kvm_get_instance(vmi)->id);
    if (NULL == dom){
        dbprint("--failed to find kvm domain\n");
        return VMI_FAILURE;
    }

    kvm_get_instance(vmi)->conn = conn;
    kvm_get_instance(vmi)->dom = dom;
    exec_memory_access(kvm_get_instance(vmi));
    return init_domain_socket(kvm_get_instance(vmi));
}

void kvm_destroy (vmi_instance_t vmi)
{
    destroy_domain_socket(kvm_get_instance(vmi));

    if (kvm_get_instance(vmi)->dom){
        virDomainFree(kvm_get_instance(vmi)->dom);
    }
    if (kvm_get_instance(vmi)->conn){
        virConnectClose(kvm_get_instance(vmi)->conn);
    }
}

unsigned long kvm_get_id_from_name (vmi_instance_t vmi, char *name)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;
    unsigned long id;

    conn = virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault, 0);
    if (NULL == conn){
        dbprint("--no connection to kvm hypervisor\n");
        return -1;
    }

    dom = virDomainLookupByName(conn, name);
    if (NULL == dom){
        dbprint("--failed to find kvm domain\n");
        return -1;
    }

    id = (unsigned long) virDomainGetID(dom);

    if (dom) virDomainFree(dom);
    if (conn) virConnectClose(conn);

    return id;
}

void kvm_set_id (vmi_instance_t vmi, unsigned long id)
{
    kvm_get_instance(vmi)->id = id;
}

void kvm_set_name (vmi_instance_t vmi, char *name)
{
    kvm_get_instance(vmi)->name = strndup(name, 500);
}

status_t kvm_get_memsize (vmi_instance_t vmi, unsigned long *size)
{
    virDomainInfo info;

    if (-1 == virDomainGetInfo(kvm_get_instance(vmi)->dom, &info)){
        dbprint("--failed to get vm info\n");
        goto error_exit;
    }
    *size = info.maxMem * 1024; // convert KBytes to bytes

    return VMI_SUCCESS;
error_exit:
    return VMI_FAILURE;
}

status_t kvm_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu)
{
    char *regs = exec_info_registers(kvm_get_instance(vmi));
    status_t ret = VMI_SUCCESS;

    switch (reg){
        case CR0:
            *value = parse_reg_value("CR0", regs);
            break;
        case CR2:
            *value = parse_reg_value("CR2", regs);
            break;
        case CR3:
            *value = parse_reg_value("CR3", regs);
            break;
        case CR4:
            *value = parse_reg_value("CR4", regs);
            break;
        default:
            ret = VMI_FAILURE;
            break;
    }

    if (regs) free(regs);
    return ret;
}

unsigned long kvm_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn)
{
    return pfn;
}

size_t kvm_read_memory (vmi_instance_t vmi, uint64_t paddr, void *buf, uint64_t len)
{
    struct request req;
    req.type = 1; // read request
    req.address = paddr;
    req.length = len;

    int nbytes = write(kvm_get_instance(vmi)->socket_fd, &req, sizeof(struct request));
    if (nbytes != sizeof(struct request)){
        return 0;
    }
    else{
        //TODO reduce the amount of data copying
        char *tmpbuf = safe_malloc(len + 1);
        nbytes = read(kvm_get_instance(vmi)->socket_fd, tmpbuf, len + 1);
        if (nbytes != len + 1){
            free(tmpbuf);
            return 0;
        }
        if (tmpbuf[0]){
            // success, copy data into user buffer
            memcpy(buf, tmpbuf + 1, len);
            return len;
        }
    }

    // default failure
    return 0;
}

void *kvm_map_page (vmi_instance_t vmi, int prot, unsigned long page)
{
//TODO this isn't mapping the page, need to rethink how page map / unmap / free / etc is handled
    unsigned long long start = page << vmi->page_shift;
    size_t size = vmi->page_size;
    void *memory = safe_malloc(size);

    if (size == kvm_read_memory(vmi, start, memory, size)){
        return memory;
    }
    else{
        dbprint("--failed to map memory\n");
        return NULL;
    }
}

int kvm_is_pv (vmi_instance_t vmi)
{
    return 0;
}

status_t kvm_test (unsigned long id, char *name)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;

    conn = virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault, 0);
    if (NULL == conn){
        dbprint("--no connection to kvm hypervisor\n");
        return VMI_FAILURE;
    }

    dom = virDomainLookupByName(conn, name);
    if (NULL == dom){
        dbprint("--failed to find kvm domain\n");
        return VMI_FAILURE;
    }

    if (dom) virDomainFree(dom);
    if (conn) virConnectClose(conn);
    return VMI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////
#else

status_t kvm_init (vmi_instance_t vmi) {return VMI_FAILURE; }
void kvm_destroy (vmi_instance_t vmi) { return; }
unsigned long kvm_get_id_from_name (vmi_instance_t vmi, char *name) { return 0; }
void kvm_set_id (vmi_instance_t vmi, unsigned long id) { return; }
void kvm_set_name (vmi_instance_t vmi, char *name) { return; }
status_t kvm_get_memsize (vmi_instance_t vmi, unsigned long *size) { return VMI_FAILURE; }
status_t kvm_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu) { return VMI_FAILURE; }
unsigned long kvm_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn) { return 0; }
void *kvm_map_page (vmi_instance_t vmi, int prot, unsigned long page) { return NULL; }
int kvm_is_pv (vmi_instance_t vmi) { return 0; }
status_t kvm_test (unsigned long id, char *name) { return VMI_FAILURE; }

#endif /* ENABLE_KVM */

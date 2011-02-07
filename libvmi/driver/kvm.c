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

#ifdef ENABLE_KVM
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

//----------------------------------------------------------------------------
// Helper functions

static char *get_arg_from_switch (int pid, char *s)
{
    char *rtnval = NULL;
    char *path = safe_malloc(100);
    snprintf(path, 100, "/proc/%d/cmdline", pid);

    int fd = open(path, O_RDONLY);
    char *buf = safe_malloc(1000);
    ssize_t len = read(fd, buf, 1000);

    char *ptr = buf;
    int found = 0;
    while (len > 0){
        ssize_t tmplen = strlen(ptr);
        if (strncmp(s, ptr, len) == 0){
            found = 1;
            ptr += tmplen + 1;
            len -= tmplen + 1;
            break;
        }
        ptr += tmplen + 1;
        len -= tmplen + 1;
    }

    if (found){
        rtnval = strndup(ptr, len);
    }

    free(buf);
    close(fd);
    return rtnval;
}

static int is_kvm_pid (char *path)
{
    int rtnval = 0;

    int fd = open(path, O_RDONLY);
    if (fd == -1){
        goto exit;
    }

    char *buf = safe_malloc(15);
    ssize_t len = read(fd, buf, 15);

    //TODO may need to generalize this line a bit
    if (strncmp("/usr/bin/kvm", buf, 13) == 0){
       rtnval = 1;
    }

exit:
    if (buf) free(buf);
    if (fd != -1) close(fd);
    return rtnval;
}

static GArray *get_kvm_pids ()
{
    GDir *dir = g_dir_open("/proc", 0, NULL);
    char *name = NULL;
    char *path = safe_malloc(100);
    GArray *rtnval = g_array_new(FALSE, FALSE, sizeof(int));

    while ((name = (char *) g_dir_read_name(dir)) != NULL){
        snprintf(path, 100, "/proc/%s/cmdline", name);
        if (is_kvm_pid(path)){
            int val = atoi(name);
            g_array_append_val(rtnval, val);
        }
    }
    g_dir_close(dir);
    free(path);

    return rtnval;
}

static void get_monitor_path (kvm_instance_t *kvm)
{
    char *monitor_path = NULL;
    char *name = (char *) virDomainGetName(kvm->dom);
    printf("--------------------\n");
    printf("name: %s\n", name);

    GArray *pids = get_kvm_pids();
    int i = 0;

    for (i = 0; i < pids->len; ++i){
        int pid = g_array_index(pids, int, i);

        // check is name is a match
        char *vmname = get_arg_from_switch(pid, "-name");
        if (strcmp(vmname, name) == 0){
            char *arg = get_arg_from_switch(pid, "-chardev");
            char *start = strstr(arg, "path=");
            if (start != NULL){
                char *end = strstr(start, ",");
                end[0] = '\0';
                monitor_path = strdup(start + 5);
            }
            else{
                free(arg);
                continue;
            }
            free(arg);
            free(vmname);
            break;
        }
        free(vmname);
    }
    g_array_free(pids, TRUE);
 
    printf("monitor_path: %s\n", monitor_path);
    printf("--------------------\n");

    //TODO use this monitor path to establish a connection to KVM/QEMU
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

//////////
    get_monitor_path(kvm_get_instance(vmi));
//////////

    return VMI_SUCCESS;
}

void kvm_destroy (vmi_instance_t vmi)
{
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
//TODO this information does not appear to be exported by libvirt ???
    switch (reg){
        case CR3:
            if (vmi->kpgd){
                *value = vmi->kpgd - vmi->page_offset;
            }
            else if (vmi->cr3){
                *value = vmi->cr3;
            }
            else{
                goto error_exit;
            }
            break;
        default:
            goto error_exit;
            break;
    }

    return VMI_SUCCESS;
error_exit:
    return VMI_FAILURE;
}

unsigned long kvm_pfn_to_mfn (vmi_instance_t vmi, unsigned long pfn)
{
    return pfn;
}

void *kvm_map_page (vmi_instance_t vmi, int prot, unsigned long page)
{
//TODO using the VIR_MEMORY_PHYSICAL option requires a recent version of libvirt (2009-07-22 or newer), check with autoconf
//TODO this isn't mapping the page, need to rethink how page map / unmap / free / etc is handled
//TODO the virDomainMemoryPeek is poorly implemented, need another option
/*
    unsigned long long start = page << vmi->page_shift;
    size_t size = vmi->page_size;
    void *memory = safe_malloc(size);

    if (-1 == virDomainMemoryPeek(kvm_get_instance(vmi)->dom, start, size, memory, VIR_MEMORY_PHYSICAL)){
        dbprint("--failed to map memory\n");
        return NULL;
    }

    return memory;
*/
    return NULL;
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

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
 * Author: Mathieu Tarral (mathieu.tarral@ssi.gouv.fr)
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

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <glib.h>
#include <libvirt/libvirt.h>
#include <libkvmi.h>

#include "private.h"
#include "msr-index.h"
#include "driver/memory_cache.h"
#include "driver/kvm/kvm.h"
#include "driver/kvm/kvm_private.h"
#include "driver/kvm/kvm_events.h"

// 2 chars for each hex + 1 space + 1 \0
#define UUID_HEX_STR_LEN (16 * 3 + 1)

enum segment_type {
    SEGMENT_SELECTOR,
    SEGMENT_BASE,
    SEGMENT_LIMIT,
    SEGMENT_ATTR
};

//----------------------------------------------------------------------------
// Helper functions

static status_t
reply_continue(kvm_instance_t *kvm, struct kvmi_dom_event *ev)
{
    void *dom = kvm->kvmi_dom;

    struct {
        struct kvmi_vcpu_hdr hdr;
        struct kvmi_event_reply common;
    } rpl = {0};

    rpl.hdr.vcpu = ev->event.common.vcpu;
    rpl.common.action = KVMI_EVENT_ACTION_CONTINUE;
    rpl.common.event = ev->event.common.event;

    if (kvm->libkvmi.kvmi_reply_event(dom, ev->seq, &rpl, sizeof(rpl)))
        return VMI_FAILURE;

    return VMI_SUCCESS;
}

static void kvm_segment_flags(const struct kvm_segment *s, x86_segment_flags_t *flags)
{
    flags->type = s->type;
    flags->s = s->s;
    flags->dpl = s->dpl;
    flags->p = s->present;
    flags->avl = s->avl;
    flags->l = s->l;
    flags->db = s->db;
    flags->g = s->g;
}

void
kvmi_regs_to_libvmi(
    struct kvm_regs *kvmi_regs,
    struct kvm_sregs *kvmi_sregs,
    x86_registers_t *libvmi_regs)
{
    x86_registers_t x86_regs = {0};
    //      standard regs
    x86_regs.rax = kvmi_regs->rax;
    x86_regs.rbx = kvmi_regs->rbx;
    x86_regs.rcx = kvmi_regs->rcx;
    x86_regs.rdx = kvmi_regs->rdx;
    x86_regs.rsi = kvmi_regs->rsi;
    x86_regs.rdi = kvmi_regs->rdi;
    x86_regs.rip = kvmi_regs->rip;
    x86_regs.rsp = kvmi_regs->rsp;
    x86_regs.rbp = kvmi_regs->rbp;
    x86_regs.rflags = kvmi_regs->rflags;
    x86_regs.r8 = kvmi_regs->r8;
    x86_regs.r9 = kvmi_regs->r9;
    x86_regs.r10 = kvmi_regs->r10;
    x86_regs.r11 = kvmi_regs->r11;
    x86_regs.r12 = kvmi_regs->r12;
    x86_regs.r13 = kvmi_regs->r13;
    x86_regs.r14 = kvmi_regs->r14;
    x86_regs.r15 = kvmi_regs->r15;
    //      special regs
    //          Control Registers
    x86_regs.cr0 = kvmi_sregs->cr0;
    x86_regs.cr2 = kvmi_sregs->cr2;
    x86_regs.cr3 = kvmi_sregs->cr3;
    x86_regs.cr4 = kvmi_sregs->cr4;
    //          CS
    x86_regs.cs_base = kvmi_sregs->cs.base;
    x86_regs.cs_limit = kvmi_sregs->cs.limit;
    x86_regs.cs_sel = kvmi_sregs->cs.selector;
    kvm_segment_flags(&kvmi_sregs->cs, &x86_regs.cs_flags);
    //          DS
    x86_regs.ds_base = kvmi_sregs->ds.base;
    x86_regs.ds_limit = kvmi_sregs->ds.limit;
    x86_regs.ds_sel = kvmi_sregs->ds.selector;
    kvm_segment_flags(&kvmi_sregs->ds, &x86_regs.ds_flags);
    //          SS
    x86_regs.ss_base = kvmi_sregs->ss.base;
    x86_regs.ss_limit = kvmi_sregs->ss.limit;
    x86_regs.ss_sel = kvmi_sregs->ss.selector;
    kvm_segment_flags(&kvmi_sregs->ss, &x86_regs.ss_flags);
    //          ES
    x86_regs.es_base = kvmi_sregs->es.base;
    x86_regs.es_limit = kvmi_sregs->es.limit;
    x86_regs.es_sel = kvmi_sregs->es.selector;
    kvm_segment_flags(&kvmi_sregs->es, &x86_regs.es_flags);
    //          FS
    x86_regs.fs_base = kvmi_sregs->fs.base;
    x86_regs.fs_limit = kvmi_sregs->fs.limit;
    x86_regs.fs_sel = kvmi_sregs->fs.selector;
    kvm_segment_flags(&kvmi_sregs->fs, &x86_regs.fs_flags);
    //          GS
    x86_regs.gs_base = kvmi_sregs->gs.base;
    x86_regs.gs_limit = kvmi_sregs->gs.limit;
    x86_regs.gs_sel = kvmi_sregs->gs.selector;
    kvm_segment_flags(&kvmi_sregs->gs, &x86_regs.gs_flags);
    //          TR
    x86_regs.tr_base = kvmi_sregs->tr.base;
    x86_regs.tr_limit = kvmi_sregs->tr.limit;
    x86_regs.tr_sel = kvmi_sregs->tr.selector;
    kvm_segment_flags(&kvmi_sregs->tr, &x86_regs.tr_flags);
    //          LDT
    x86_regs.ldt_base = kvmi_sregs->ldt.base;
    x86_regs.ldt_limit = kvmi_sregs->ldt.limit;
    x86_regs.ldt_sel = kvmi_sregs->ldt.selector;
    kvm_segment_flags(&kvmi_sregs->ldt, &x86_regs.ldt_flags);
    // assign
    (*libvmi_regs) = x86_regs;
}

void *
kvm_get_memory_patch(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if (!kvm->kvmi_dom)
        return NULL;

    char* buffer = g_try_malloc0(length);
    if (!buffer)
        return NULL;

    if (kvm->libkvmi.kvmi_read_physical(kvm->kvmi_dom, paddr, buffer, length) < 0) {
        g_free(buffer);
        return NULL;
    }

    return buffer;
}

void *
kvm_get_memory_kvmi(vmi_instance_t vmi, addr_t paddr, uint32_t length)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    void *buffer;

    if (!kvm->kvmi_dom)
        return NULL;

    buffer = g_try_malloc0(length);
    if (!buffer)
        return NULL;

    if (kvm->libkvmi.kvmi_read_physical(kvm->kvmi_dom, paddr, buffer, length) < 0) {
        g_free(buffer);
        return NULL;
    }

    return buffer;
}

void
kvm_release_memory(
    vmi_instance_t UNUSED(vmi),
    void *memory,
    size_t UNUSED(length))
{
    if (memory)
        free(memory);
}

status_t
kvm_put_memory(vmi_instance_t vmi,
               addr_t paddr,
               uint32_t length,
               void *buf)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if (!kvm->kvmi_dom)
        return VMI_FAILURE;

    if (kvm->libkvmi.kvmi_write_physical(kvm->kvmi_dom, paddr, buf, length) < 0)
        return VMI_FAILURE;

    /*
     * We need to refresh the page cache after a page is written to
     * because it might have been a copy-on-write page. After this
     * write the mapping changes but the cached reference is to the
     * old (origin) page.
     */
    int num_pages = ((paddr + length - 1) >> vmi->page_shift) - (paddr >> vmi->page_shift) + 1;
    for (int i = 0; i < num_pages; i++) {
        memory_cache_remove(vmi, ((paddr >> vmi->page_shift) + i) << vmi->page_shift);
    }

    return VMI_SUCCESS;
}

/**
 * Setup KVM live (i.e. KVM patch or KVM native) mode.
 * If KVM patch has been setup before, resume it.
 * If KVM patch hasn't been setup but is available, setup
 * KVM patch, otherwise setup KVM native.
 */
status_t
kvm_setup_live_mode(
    vmi_instance_t vmi)
{
    memory_cache_destroy(vmi);
    memory_cache_init(vmi, kvm_get_memory_kvmi, kvm_release_memory, 1);
    return VMI_SUCCESS;
}

//----------------------------------------------------------------------------
// KVMI-Specific Interface Functions (no direction mapping to driver_*)

static int
new_guest_cb(
    void *dom,
    unsigned char (*uuid)[16],
    void *ctx)
{
    if (!dom || !uuid || !ctx) {
        errprint("Invalid parameters in KVMi new guest callback");
        return 1;
    }

    kvm_instance_t *kvm = ctx;
    char uuid_str[UUID_HEX_STR_LEN] = {0};
    memset(uuid_str, 0, UUID_HEX_STR_LEN);

    // convert UUID hex to string
    unsigned int current_size = 0;
    for (long unsigned int k = 0; k < sizeof(*uuid); k++ ) {
        if (k < sizeof(*uuid) - 1 ) {
            sprintf(&uuid_str[current_size], "%02X ", ( *uuid )[k] );
            current_size += 3;
        } else {
            // no space
            sprintf(&uuid_str[current_size], "%02X", ( *uuid )[k] );
            current_size += 2;
        }
    }
    uuid_str[current_size] = '\0';
    // get fd
    int fd = kvm->libkvmi.kvmi_connection_fd(dom);
    // remove unused variable if no debug
    (void)fd;

    // get version
    unsigned int version = 0;
    if (kvm->libkvmi.kvmi_get_version(dom, &version) != 0) {
        errprint("Failed to get KVMi version\n");
        return 1;
    }
    // print infos
    dbprint(VMI_DEBUG_KVM, "--KVMi new guest:\n");
    dbprint(VMI_DEBUG_KVM, "--    UUID: %s\n", uuid_str);
    dbprint(VMI_DEBUG_KVM, "--    FD: %d\n", fd);
    dbprint(VMI_DEBUG_KVM, "--    Protocol version: %u\n", version);
    pthread_mutex_lock(&kvm->kvm_connect_mutex);
    /*
     * If kvmi_dom is not NULL it means this is a reconnection.
     * The previous connection was closed somehow.
     */
    if (kvm->kvmi_dom)
        kvm->libkvmi.kvmi_domain_close(kvm->kvmi_dom, true);
    kvm->kvmi_dom = dom;
    pthread_cond_signal(&kvm->kvm_start_cond);
    pthread_mutex_unlock(&kvm->kvm_connect_mutex);

    return 0;
}

static int handshake_cb(
    const struct kvmi_qemu2introspector *qemu,
    struct kvmi_introspector2qemu *intro,
    void *ctx)
{
    (void)intro;
    (void)ctx;
    dbprint(VMI_DEBUG_KVM, "--KVMi handshake:\n");
    dbprint(VMI_DEBUG_KVM, "--    VM name: %s\n", qemu->name);
    char start_date[64];
    const char *format = "%H:%M:%S - %a %b %d %Y";
    time_t starttime = (time_t) qemu->start_time;
    struct tm *tm = NULL;
    tm = localtime(&starttime);
    if (strftime(start_date, sizeof(start_date), format, tm) <= 0) {
        errprint("Failed to convert time to string\n");
    } else {
        dbprint(VMI_DEBUG_KVM, "--    VM start time: %s\n", start_date);
    }
    return 0;
}

static void
log_cb(
    kvmi_log_level level,
    const char *s,
    void *ctx)
{
    (void)ctx;
    (void)s;
    switch (level) {
        case KVMI_LOG_LEVEL_ERROR:
            dbprint(VMI_DEBUG_KVM, "--KVMi Error: %s\n", s);
            break;
        case KVMI_LOG_LEVEL_WARNING:
            dbprint(VMI_DEBUG_KVM, "--KVMi Warning: %s\n", s);
            break;
        case KVMI_LOG_LEVEL_INFO:
            dbprint(VMI_DEBUG_KVM, "--KVMi Info: %s\n", s);
            break;
        case KVMI_LOG_LEVEL_DEBUG:
            dbprint(VMI_DEBUG_KVM, "--KVMi Debug: %s\n", s);
            break;
        default:
            errprint("Unhandled KVMi log level %d\n", level);
    }
}

static bool
init_kvmi(
    kvm_instance_t *kvm,
    const char *sock_path)
{
    int err = -1;

    pthread_mutex_init(&kvm->kvm_connect_mutex, NULL);
    pthread_cond_init(&kvm->kvm_start_cond, NULL);
    kvm->kvmi_dom = NULL;

    pthread_mutex_lock(&kvm->kvm_connect_mutex);
    if (atoi(sock_path) > 0) {
        kvm->kvmi = kvm->libkvmi.kvmi_init_vsock(atoi(sock_path), new_guest_cb, handshake_cb, kvm);
    } else {
        kvm->kvmi = kvm->libkvmi.kvmi_init_unix_socket(sock_path, new_guest_cb, handshake_cb, kvm);
    }

    if (kvm->kvmi) {
        struct timeval now;
        if (gettimeofday(&now, NULL) == 0) {
            struct timespec t = {};
            t.tv_sec = now.tv_sec + 10;
            err = pthread_cond_timedwait(&kvm->kvm_start_cond, &kvm->kvm_connect_mutex, &t);
        }
    }
    pthread_mutex_unlock(&kvm->kvm_connect_mutex);

    if (err) {
        /*
         * The libkvmi may accept the connection after timeout
         * and our callback can set kvm->kvmi_dom. So, we must
         * stop the accepting thread first.
         */
        kvm->libkvmi.kvmi_uninit(kvm->kvmi);
        kvm->kvmi = NULL;
        /* From this point, kvm->kvmi_dom won't be touched. */
        kvm->libkvmi.kvmi_domain_close(kvm->kvmi_dom, true);
        return false;
    }

    // query and display supported features
    struct kvmi_features features = {0};
    kvm->libkvmi.kvmi_spp_support(kvm->kvmi_dom, (bool*)&features.spp);
    kvm->libkvmi.kvmi_vmfunc_support(kvm->kvmi_dom, (bool*)&features.vmfunc);
    kvm->libkvmi.kvmi_eptp_support(kvm->kvmi_dom, (bool*)&features.eptp);
    kvm->libkvmi.kvmi_ve_support(kvm->kvmi_dom, (bool*)&features.ve);

    dbprint(VMI_DEBUG_KVM, "--KVMi features:\n");
    // available in 2013 on Intel Haswell
    dbprint(VMI_DEBUG_KVM, "--    VMFUNC: %s\n", features.vmfunc ? "Yes" : "No");
    dbprint(VMI_DEBUG_KVM, "--    EPTP: %s\n", features.eptp ? "Yes" : "No");
    dbprint(VMI_DEBUG_KVM, "--    VE: %s\n", features.ve ? "Yes" : "No");
    // available in 2019 on Intel Ice Lake
    dbprint(VMI_DEBUG_KVM, "--    SPP: %s\n", features.spp ? "Yes" : "No");

    return true;
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t
kvm_init(
    vmi_instance_t vmi,
    uint32_t UNUSED(init_flags),
    vmi_init_data_t* UNUSED(init_data))
{
    kvm_instance_t *kvm = g_try_malloc0(sizeof(kvm_instance_t));
    if (!kvm)
        return VMI_FAILURE;

    if ( VMI_FAILURE == create_libkvmi_wrapper(kvm) ) {
        g_free(kvm);
        return VMI_FAILURE;
    }

    if ( VMI_FAILURE == create_libvirt_wrapper(kvm) ) {
        g_free(kvm);
        return VMI_FAILURE;
    }

    virConnectPtr conn = kvm->libvirt.virConnectOpenAuth("qemu:///system", kvm->libvirt.virConnectAuthPtrDefault, 0);
    if (NULL == conn) {
        dbprint(VMI_DEBUG_KVM, "--no connection to kvm hypervisor\n");
        g_free(kvm);
        return VMI_FAILURE;
    }

    kvm->conn = conn;

    vmi->driver.driver_data = (void*)kvm;

    return VMI_SUCCESS;
}

static void
kvm_close_vmi(vmi_instance_t vmi, kvm_instance_t *kvm)
{
    // events ?
    if (kvm->kvmi_dom && (vmi->init_flags & VMI_INIT_EVENTS)) {
        kvm_events_destroy(vmi);
    }

    if (kvm->sstep_enabled) {
        g_free(kvm->sstep_enabled);
        kvm->sstep_enabled = NULL;
    }

    if (kvm->pause_events_list) {
        g_free(kvm->pause_events_list);
        kvm->pause_events_list = NULL;
    }

    if (kvm->kvmi_dom) {
        kvm->libkvmi.kvmi_domain_close(kvm->kvmi_dom, true);
        kvm->kvmi_dom = NULL;
    }

    if (kvm->kvmi) {
        kvm->libkvmi.kvmi_uninit(kvm->kvmi);
        kvm->kvmi = NULL;
    }

    if (kvm->dom) {
        kvm->libvirt.virDomainFree(kvm->dom);
        kvm->dom = NULL;
    }

    if (kvm->conn) {
        kvm->libvirt.virConnectClose(kvm->conn);
        kvm->conn = NULL;
    }
}

status_t
kvm_init_vmi(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t* init_data)
{
    (void)init_flags; // unused
    vmi_init_data_entry_t init_entry;
    char *socket_path = NULL;

    // a socket path is required to init kvmi
    if (!init_data) {
        dbprint(VMI_DEBUG_KVM, "--kvmi need a socket path to be specified\n");
        return VMI_FAILURE;
    }
    // check we have at least on entry
    if (init_data->count < 1) {
        dbprint(VMI_DEBUG_KVM, "--empty init data\n");
        return VMI_FAILURE;
    }
    init_entry = init_data->entry[0];
    // check init_data type
    if (init_entry.type != VMI_INIT_DATA_KVMI_SOCKET) {
        dbprint(VMI_DEBUG_KVM, "--wrong init data type\n");
        return VMI_FAILURE;
    }
    socket_path = (char*) init_entry.data;
    dbprint(VMI_DEBUG_KVM, "--KVMi socket path: %s\n", socket_path);

    kvm_instance_t *kvm = kvm_get_instance(vmi);
    kvm->dom = kvm->libvirt.virDomainLookupByID(kvm->conn, kvm->id);
    if (NULL == kvm->dom) {
        dbprint(VMI_DEBUG_KVM, "--failed to find kvm domain\n");
        return VMI_FAILURE;
    }

    // get the libvirt version
    unsigned long libVer = 0;

    if (kvm->libvirt.virConnectGetLibVersion(kvm->conn, &libVer) != 0) {
        dbprint(VMI_DEBUG_KVM, "--failed to get libvirt version\n");
        goto err_exit;
    }
    dbprint(VMI_DEBUG_KVM, "--libvirt version %lu\n", libVer);

    vmi->vm_type = NORMAL;

    // configure log cb before connecting
    kvm->libkvmi.kvmi_set_log_cb(log_cb, (void*)vmi);

    dbprint(VMI_DEBUG_KVM, "--Connecting to KVMI...\n");
    if (!init_kvmi(kvm,  socket_path)) {
        dbprint(VMI_DEBUG_KVM, "--KVMI failed\n");
        goto err_exit;
    }
    dbprint(VMI_DEBUG_KVM, "--KVMI connected\n");

    // get VCPU count
    if (kvm->libkvmi.kvmi_get_vcpu_count(kvm->kvmi_dom, &vmi->num_vcpus)) {
        dbprint(VMI_DEBUG_KVM, "--Fail to get VCPU count: %s\n", strerror(errno));
        goto err_exit;
    }
    dbprint(VMI_DEBUG_KVM, "--VCPU count: %d\n", vmi->num_vcpus);

    // init pause events array
    kvm->pause_events_list = g_try_new0(struct kvmi_dom_event*, vmi->num_vcpus);
    if (!kvm->pause_events_list)
        goto err_exit;

    // init singlestep enabled array
    kvm->sstep_enabled = g_try_new0(bool, vmi->num_vcpus);
    if (!kvm->sstep_enabled)
        goto err_exit;

    // events ?
    if (init_flags & VMI_INIT_EVENTS) {
        if (VMI_FAILURE == kvm_events_init(vmi, init_flags, init_data))
            return VMI_FAILURE;
    }

    return kvm_setup_live_mode(vmi);
err_exit:
    kvm_close_vmi(vmi, kvm);
    return VMI_FAILURE;
}

void
kvm_destroy(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    dbprint(VMI_DEBUG_KVM, "--Destroying KVM driver\n");

    if (kvm) {
        kvm_close_vmi(vmi, kvm);

        dlclose(kvm->libkvmi.handle);
        dlclose(kvm->libvirt.handle);
        dlclose(kvm->libvirt.handle_qemu);
        g_free(kvm);
    }
}

status_t
kvm_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!allocated_ram_size || !maximum_physical_address)
        return VMI_FAILURE;
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    unsigned long long max_gfn;
    if (kvm->libkvmi.kvmi_get_maximum_gfn(kvm->kvmi_dom, &max_gfn)) {
        errprint("--failed to get maximum gfn\n");
        return VMI_FAILURE;
    }

    *allocated_ram_size = max_gfn * vmi->page_size;
    *maximum_physical_address = max_gfn << vmi->page_shift;
    return VMI_SUCCESS;
}

status_t kvm_request_page_fault (
    vmi_instance_t vmi,
    unsigned long vcpu,
    uint64_t virtual_address,
    uint32_t error_code)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("Invalid vmi handle\n");
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("Invalid kvm/kvmi handles\n");
        return VMI_FAILURE;
    }
#endif
    if (kvm->libkvmi.kvmi_inject_exception(kvm->kvmi_dom, vcpu, virtual_address, error_code, PF_VECTOR))
        return VMI_FAILURE;

    dbprint(VMI_DEBUG_KVM, "--Page fault injected at 0x%"PRIx64"\n", virtual_address);
    return VMI_SUCCESS;
}

status_t kvm_get_tsc_info(
    vmi_instance_t vmi,
    __attribute__((unused)) uint32_t *tsc_mode,
    __attribute__((unused)) uint64_t *elapsed_nsec,
    uint32_t *gtsc_khz,
    __attribute__((unused)) uint32_t *incarnation)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("Invalid vmi handle\n");
        return VMI_FAILURE;
    }
#endif
    // checking only gtsc_khz parameter
#ifdef ENABLE_SAFETY_CHECKS
    if (!gtsc_khz) {
        errprint("Invalid gtsc_khz pointer\n");
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("Invalid kvm/kvmi handles\n");
        return VMI_FAILURE;
    }
#endif
    dbprint(VMI_DEBUG_KVM, "--Get TSC info\n");

    unsigned long long speed = 0;
    if (kvm->libkvmi.kvmi_get_tsc_speed(kvm->kvmi_dom, &speed))
        return VMI_FAILURE;

    // convert to KHz and assign gtsc_khz
    (*gtsc_khz) = speed / 1000;

    return VMI_SUCCESS;
}

status_t
kvm_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
    if (!value) {
        errprint("%s: value is invalid\n", __func__);
        return VMI_FAILURE;
    }

    // TODO: add some sort of caching to avoir fetching
    // all registers everytime ?
    registers_t regs = {0};
    if (VMI_FAILURE == kvm_get_vcpuregs(vmi, &regs, (unsigned short)vcpu))
        return VMI_FAILURE;

    switch (reg) {
        case RAX:
            *value = regs.x86.rax;
            break;
        case RBX:
            *value = regs.x86.rbx;
            break;
        case RCX:
            *value = regs.x86.rcx;
            break;
        case RDX:
            *value = regs.x86.rdx;
            break;
        case RBP:
            *value = regs.x86.rbp;
            break;
        case RSI:
            *value = regs.x86.rsi;
            break;
        case RDI:
            *value = regs.x86.rdi;
            break;
        case RSP:
            *value = regs.x86.rsp;
            break;
        case R8:
            *value = regs.x86.r8;
            break;
        case R9:
            *value = regs.x86.r9;
            break;
        case R10:
            *value = regs.x86.r10;
            break;
        case R11:
            *value = regs.x86.r11;
            break;
        case R12:
            *value = regs.x86.r12;
            break;
        case R13:
            *value = regs.x86.r13;
            break;
        case R14:
            *value = regs.x86.r14;
            break;
        case R15:
            *value = regs.x86.r15;
            break;
        case RIP:
            *value = regs.x86.rip;
            break;
        case RFLAGS:
            *value = regs.x86.rflags;
            break;
        case CR0:
            *value = regs.x86.cr0;
            break;
        case CR2:
            *value = regs.x86.cr2;
            break;
        case CR3:
            *value = regs.x86.cr3;
            break;
        case CR4:
            *value = regs.x86.cr4;
            break;
        case FS_BASE:
            *value = regs.x86.fs_base;
            break;
        case GS_BASE:
            *value = regs.x86.gs_base;
            break;
        case SYSENTER_CS:
            *value = regs.x86.sysenter_cs;
            break;
        case SYSENTER_ESP:
            *value = regs.x86.sysenter_esp;
            break;
        case SYSENTER_EIP:
            *value = regs.x86.sysenter_eip;
            break;
        case MSR_EFER:
            *value = regs.x86.msr_efer;
            break;
        case MSR_STAR:
            *value = regs.x86.msr_star;
            break;
        case MSR_LSTAR:
            *value = regs.x86.msr_lstar;
            break;
        case MSR_CSTAR:
            *value = regs.x86.msr_cstar;
            break;
        case GDTR_BASE:
            *value = regs.x86.gdtr_base;
            break;
        case GDTR_LIMIT:
            *value = regs.x86.gdtr_limit;
            break;
        case IDTR_BASE:
            *value = regs.x86.idtr_base;
            break;
        case IDTR_LIMIT:
            *value = regs.x86.idtr_limit;
            break;
        default:
            dbprint(VMI_DEBUG_KVM, "--Reading register %"PRIu64" not implemented\n", reg);
            return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t
kvm_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *registers,
    unsigned long vcpu)
{
    status_t ret = VMI_FAILURE;
    struct kvm_regs regs = {0};
    struct kvm_sregs sregs = {0};
    struct kvm_msrs *msrs = (struct kvm_msrs*)calloc(1, sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry) * 7);
    struct kvm_msr_entry *msr_entries = (struct kvm_msr_entry*)((unsigned char*)msrs + sizeof(struct kvm_msrs));
    unsigned int mode = 0;
    x86_registers_t *x86 = &registers->x86;
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if ( !msrs )
        return ret;

    msrs->nmsrs = 7;
    msr_entries[0].index = msr_index[MSR_IA32_SYSENTER_CS];
    msr_entries[1].index = msr_index[MSR_IA32_SYSENTER_ESP];
    msr_entries[2].index = msr_index[MSR_IA32_SYSENTER_EIP];
    msr_entries[3].index = msr_index[MSR_EFER];
    msr_entries[4].index = msr_index[MSR_STAR];
    msr_entries[5].index = msr_index[MSR_LSTAR];
    msr_entries[6].index = msr_index[MSR_CSTAR];

#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm->kvmi_dom)
        goto done;
#endif

    if (kvm->libkvmi.kvmi_get_registers(kvm->kvmi_dom, vcpu, &regs, &sregs, msrs, &mode))
        goto done;

    kvmi_regs_to_libvmi(&regs, &sregs, x86);
    x86->sysenter_cs = msr_entries[0].data;
    x86->sysenter_esp = msr_entries[1].data;
    x86->sysenter_eip = msr_entries[2].data;
    x86->msr_efer = msr_entries[3].data;
    x86->msr_star = msr_entries[4].data;
    x86->msr_lstar = msr_entries[5].data;
    x86->msr_cstar = msr_entries[6].data;
    x86->gdtr_base = sregs.gdt.base;
    x86->gdtr_limit = sregs.gdt.limit;
    x86->idtr_base = sregs.idt.base;
    x86->idtr_limit = sregs.idt.limit;

    ret = VMI_SUCCESS;

done:
    free(msrs);
    return ret;
}

status_t
kvm_set_vcpureg(vmi_instance_t vmi,
                uint64_t value,
                reg_t reg,
                unsigned long vcpu)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    unsigned int mode = 0;
    struct kvm_regs regs = {0};
    struct kvm_sregs sregs = {0};
    struct kvm_msrs msrs = {0};

#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm->kvmi_dom)
        return VMI_FAILURE;
#endif

    if (kvm->libkvmi.kvmi_get_registers(kvm->kvmi_dom, vcpu, &regs, &sregs, &msrs, &mode) < 0) {
        return VMI_FAILURE;
    }

    // This could use a macro or something
    switch (reg) {
        case RAX:
            regs.rax = value;
            break;
        case RBX:
            regs.rbx = value;
            break;
        case RCX:
            regs.rcx = value;
            break;
        case RDX:
            regs.rdx = value;
            break;
        case RSI:
            regs.rsi = value;
            break;
        case RDI:
            regs.rdi = value;
            break;
        case RSP:
            regs.rsp = value;
            break;
        case RBP:
            regs.rbp = value;
            break;
        case R8:
            regs.r8 = value;
            break;
        case R9:
            regs.r9 = value;
            break;
        case R10:
            regs.r10 = value;
            break;
        case R11:
            regs.r11 = value;
            break;
        case R12:
            regs.r12 = value;
            break;
        case R13:
            regs.r13 = value;
            break;
        case R14:
            regs.r14 = value;
            break;
        case R15:
            regs.r15 = value;
            break;
        case RIP:
            regs.rip = value;
            break;
        case RFLAGS:
            regs.rflags = value;
            break;
        default:
            return VMI_FAILURE;
    }

    if (kvm->libkvmi.kvmi_set_registers(kvm->kvmi_dom, vcpu, &regs) < 0) {
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t
kvm_set_vcpuregs(vmi_instance_t vmi,
                 registers_t *registers,
                 unsigned long vcpu)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    if (!kvm->kvmi_dom)
        return VMI_FAILURE;
    struct x86_regs *x86 = &registers->x86;
    struct kvm_regs regs = {
        .rax = x86->rax,
        .rbx = x86->rbx,
        .rcx = x86->rcx,
        .rdx = x86->rdx,
        .rsi = x86->rsi,
        .rdi = x86->rdi,
        .rsp = x86->rsp,
        .rbp = x86->rbp,
        .r8  = x86->r8,
        .r9  = x86->r9,
        .r10 = x86->r10,
        .r11 = x86->r11,
        .r12 = x86->r12,
        .r13 = x86->r13,
        .r14 = x86->r14,
        .r15 = x86->r15,
        .rip = x86->rip,
        .rflags = x86->rflags
    };
    if (kvm->libkvmi.kvmi_set_registers(kvm->kvmi_dom, vcpu, &regs) < 0) {
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

status_t
kvm_pause_vm(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if (kvm->pause_count > 0) {
        kvm->pause_count++;
        dbprint(VMI_DEBUG_KVM, "--Pause count: %d\n", kvm->pause_count);
        return VMI_SUCCESS;
    }

    // pause vcpus
    if (kvm->libkvmi.kvmi_pause_all_vcpus(kvm->kvmi_dom, vmi->num_vcpus)) {
        errprint("%s: Failed to pause domain: %s\n", __func__, strerror(errno));
        return VMI_FAILURE;
    }

    kvm->pause_count = 1;

    dbprint(VMI_DEBUG_KVM, "--We should receive %u pause events\n", vmi->num_vcpus);

    return VMI_SUCCESS;
}

status_t
kvm_resume_vm(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    // already resumed?
    if (kvm->pause_count <= 0)
        return VMI_SUCCESS;

    if (kvm->pause_count > 1) {
        kvm->pause_count--;
        dbprint(VMI_DEBUG_KVM, "--Pause count: %d\n", kvm->pause_count);
        return VMI_SUCCESS;
    }

    // iterate over pause_events_list and unpause every single vcpu by sending a continue reply for each pause event
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        struct kvmi_dom_event *ev = NULL;

        // wait until the pause event for the current vcpu is received
        while (!kvm->pause_events_list[vcpu]) {
            dbprint(VMI_DEBUG_KVM, "--Waiting to receive PAUSE_VCPU event for vcpu %u\n", vcpu);
            if (kvm_process_events_with_timeout(vmi, 100) == VMI_FAILURE) {
                return VMI_FAILURE;
            }
        }

        dbprint(VMI_DEBUG_KVM, "--Removing PAUSE_VCPU event from the buffer\n");
        ev = kvm->pause_events_list[vcpu];
        kvm->pause_events_list[vcpu] = NULL;

        // handle event
        dbprint(VMI_DEBUG_KVM, "--Sending continue reply\n");
        if (reply_continue(kvm, ev) == VMI_FAILURE) {
            errprint("%s: Failed to send continue reply\n", __func__);
            free(ev);
            return VMI_FAILURE;
        }
        free(ev);
    }

    kvm->pause_count = 0;

    return VMI_SUCCESS;
}

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
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>
#include <math.h>
#include <glib/gstdio.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include <libvirt/libvirt-qemu.h>
#include <json-c/json.h>

#include "private.h"
#include "driver/driver_wrapper.h"
#include "driver/memory_cache.h"
#include "driver/kvm/kvm.h"
#include "driver/kvm/kvm_private.h"


#define QMP_CMD_LENGTH 256

#ifdef HAVE_LIBVMI_REQUEST
#  include <qemu/libvmi_request.h>
#else

// request struct matches a definition in qemu source code
struct request {
    uint64_t type;   // 0 quit, 1 read, 2 write, ... rest reserved
    uint64_t address;   // address to read from OR write to
    uint64_t length;    // number of bytes to read OR write
};

#endif // !HAVE_LIBVMI_REQUEST

enum segment_type {
    SEGMENT_SELECTOR,
    SEGMENT_BASE,
    SEGMENT_LIMIT,
    SEGMENT_ATTR
};

//----------------------------------------------------------------------------
// Helper functions

//
// QMP Command Interactions
static char *
exec_qmp_cmd(
    kvm_instance_t *kvm,
    char *query)
{
    char *output = NULL;

    dbprint(VMI_DEBUG_KVM, "--qmp: %s\n", query);

    int ret = kvm->libvirt.virDomainQemuMonitorCommand(kvm->dom, query, &output, VIR_DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT);
    if (ret < 0) {
        errprint("Failed to execute qemu monitor command\n");
        return NULL;
    }

    return output;
}

static char *
exec_info_registers(
    kvm_instance_t *kvm)
{
    char *query =
        "{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"info registers\"}}";
    return exec_qmp_cmd(kvm, query);
}

static struct json_object *
exec_info_version(
    kvm_instance_t *kvm)
{
    char *query =
        "{\"execute\": \"query-version\"}";
    char *output = exec_qmp_cmd(kvm, query);
    struct json_object *jobj = NULL;

    if (output) {
        jobj = json_tokener_parse(output);
        free(output);
    }

    return jobj;
}

static char *
exec_info_mtree(
    kvm_instance_t *kvm)
{
    char *query =
        "{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"info mtree\"}}";
    return exec_qmp_cmd(kvm, query);
}

static char *
exec_memory_access(
    kvm_instance_t *kvm)
{
    char *tmpfile = tempnam("/tmp", "vmi");
    char *query = (char *) g_try_malloc0(QMP_CMD_LENGTH);

    if ( !query )
        return NULL;

    int rc = snprintf(query,
                      QMP_CMD_LENGTH,
                      "{\"execute\": \"pmemaccess\", \"arguments\": {\"path\": \"%s\"}}",
                      tmpfile);
    if (rc < 0 || rc >= QMP_CMD_LENGTH) {
        g_free(query);
        errprint("Failed to properly format `pmemaccess` command\n");
        return NULL;
    }
    kvm->ds_path = strdup(tmpfile);
    free(tmpfile);

    char *output = exec_qmp_cmd(kvm, query);

    g_free(query);
    return output;
}

static char *
exec_xp(
    kvm_instance_t *kvm,
    int numwords,
    addr_t paddr)
{
    char *query = (char *) g_try_malloc0(QMP_CMD_LENGTH);
    if ( !query )
        return NULL;

    int rc = snprintf(query,
                      QMP_CMD_LENGTH,
                      "{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"xp /%dwx 0x%lx\"}}",
                      numwords, paddr);
    if (rc < 0 || rc >= QMP_CMD_LENGTH) {
        g_free(query);
        errprint("Failed to properly format `human-monitor-command` command\n");
        return NULL;
    }

    char *output = exec_qmp_cmd(kvm, query);

    g_free(query);
    return output;
}

static reg_t
parse_reg_value(
    char *regname,
    char *ir_output)
{
    if (NULL == ir_output || NULL == regname) {
        return 0;
    }

    char *ptr = strcasestr(ir_output, regname);

    if (NULL != ptr) {
        ptr += strlen(regname) + 1;
        return (reg_t) strtoull(ptr, (char **) NULL, 16);
    } else {
        return 0;
    }
}

static reg_t
parse_seg_reg_value(
    char *regname,
    char *ir_output,
    int type)
{
    int offset;
    char *ptr, *tmp_ptr;
    char keyword[5] = { [0 ... 4] = '\0' };

    if (NULL == ir_output || NULL == regname) {
        return 0;
    }

    strncpy(keyword, regname, 3);
    if (strlen(regname) == 2)
        strcat(keyword, " =");
    else
        strcat(keyword, "=");

    if (NULL == (ptr = strcasestr(ir_output, keyword)))
        return 0;

    tmp_ptr = ptr;
    switch (type) {
        case SEGMENT_SELECTOR:
            offset = 4;
            break;
        case SEGMENT_BASE:
            offset = 9;
            break;
        case SEGMENT_LIMIT:
            tmp_ptr += 9;
            if (8 == strlen(tmp_ptr))
                offset = 18;
            else
                offset = 26;
            break;
        case SEGMENT_ATTR:
            tmp_ptr += 9;
            if (8 == strlen(tmp_ptr))
                offset = 27;
            else
                offset = 35;
            break;
        default:
            return 0;
    }

    ptr += offset;
    return (reg_t) strtoull(ptr, (char **) NULL, 16);
}

static addr_t
parse_mtree(char *mtree_output)
{
    char *ptr = NULL;
    char *tmp = NULL;
    char *line = NULL;
    const char *line_delim = "\\";
    const char *above_4g_delim = "-";
    const char *above_4g = "alias ram-above-4g";
    char *above_4g_line = NULL;
    addr_t value = 0;

    // for each line
    line = strtok_r(mtree_output, line_delim, &tmp);
    do {
        // check for above 4g
        if (strstr(line, above_4g) != NULL) {
            above_4g_line = strdup(line);
            break;
        }
        // consume r\n
        line = strtok_r(NULL, "n", &tmp);
        if (line == NULL)
            return 0;
    } while ((line = strtok_r(NULL, line_delim, &tmp)) != NULL);

    // did we find above 4g ?
    if (above_4g_line == NULL)
        goto out_error;

    // example of content for above_4g_str:
    //    0000000100000000-000000013fffffff (prio 0, RW): alias ram-above-4g @pc.ram 00000000c0000000-00000000ffffffff
    // we want to extract 000000013fffffff
    tmp = NULL;
    ptr = strtok_r(above_4g_line, above_4g_delim, &tmp);
    if (ptr == NULL)
        goto out_error;

    // ptr: 0000000100000000
    ptr = strtok_r(NULL, above_4g_delim, &tmp);
    if (ptr == NULL)
        goto out_error;
    // ptr: 000000013fffffff (prio 0, RW): alias ram
    value = (addr_t) strtoll(ptr, (char **) NULL, 16) + 1;
out_error:
    if (above_4g_line)
        free(above_4g_line);
    return value;
}

status_t
exec_memory_access_success(
    char *status)
{
    if (NULL == status) {
        return VMI_FAILURE;
    }

    char *ptr = strcasestr(status, "CommandNotFound");

    if (NULL == ptr) {
        return VMI_SUCCESS;
    } else {
        return VMI_FAILURE;
    }
}

/**
 * note:
 * "kvm_patch" here means the feature in pmemaccess patch (kvm-physmem-access_x.x.x.patch);
 */
static status_t
test_using_kvm_patch(
    kvm_instance_t *kvm)
{
    if (kvm->socket_fd) {
        return VMI_SUCCESS;
    } else {
        return VMI_FAILURE;
    }
}

//
// Domain socket interactions (for memory access from KVM-QEMU)
static status_t
init_domain_socket(
    kvm_instance_t *kvm)
{
    struct sockaddr_un address;
    int socket_fd;
    size_t address_length;

    socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        dbprint(VMI_DEBUG_KVM, "--socket() failed\n");
        return VMI_FAILURE;
    }

    address.sun_family = AF_UNIX;
    address_length =
        sizeof(address.sun_family) + sprintf(address.sun_path, "%s",
                kvm->ds_path);

    if (connect(socket_fd, (struct sockaddr *) &address, address_length)
            != 0) {
        dbprint(VMI_DEBUG_KVM, "--connect() failed to %s, %s\n", kvm->ds_path, strerror(errno));
        close(socket_fd);
        return VMI_FAILURE;
    }

    kvm->socket_fd = socket_fd;
    return VMI_SUCCESS;
}

static void
destroy_domain_socket(
    kvm_instance_t *kvm)
{
    if (VMI_SUCCESS == test_using_kvm_patch(kvm)) {
        struct request req;

        req.type = 0;   // quit
        req.address = 0;
        req.length = 0;
        if (write(kvm->socket_fd, &req, sizeof(struct request)) < 0)
            dbprint(VMI_DEBUG_KVM, "--failed to write to socket (%s)\n", strerror(errno));
        close(kvm->socket_fd);
    }
}

void *
kvm_get_memory_patch(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    char *buf = g_try_malloc0(length + 1);
    if ( !buf )
        return NULL;

    struct request req;

    req.type = 1;   // read request
    req.address = (uint64_t) paddr;
    req.length = (uint64_t) length;

    int nbytes =
        write(kvm_get_instance(vmi)->socket_fd, &req,
              sizeof(struct request));
    if (nbytes != sizeof(struct request)) {
        goto error_exit;
    } else {
        // get the data from kvm
        nbytes = read(kvm_get_instance(vmi)->socket_fd, buf, length + 1);
        if ( nbytes <= 0 )
            goto error_exit;

        if ( (uint32_t)nbytes != (length + 1) )
            goto error_exit;

        // check that kvm thinks everything is ok by looking at the last byte
        // of the buffer, 0 is failure and 1 is success
        if (buf[length]) {
            // success, return pointer to buf
            return buf;
        }
    }

    // default failure
error_exit:
    if (buf)
        free(buf);
    return NULL;
}

void *
kvm_get_memory_native(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    int numwords = ceil(length / 4);
    char *buf = g_try_malloc0(numwords * 4);
    char *bufstr = exec_xp(kvm_get_instance(vmi), numwords, paddr);
    char *paddrstr = g_try_malloc0(32);

    if ( !buf || !bufstr || !paddrstr )
        goto error;

    int rc = snprintf(paddrstr, 32, "%.16lx", paddr);
    if (rc < 0 || rc >= 32) {
        errprint("Failed to properly format physical address\n");
        goto error;
    }

    char *ptr = strcasestr(bufstr, paddrstr);
    int i = 0, j = 0;

    while (i < numwords && NULL != ptr) {
        ptr += strlen(paddrstr) + 2;

        for (j = 0; j < 4; ++j) {
            uint32_t value = strtol(ptr, (char **) NULL, 16);

            memcpy(buf + i * 4, &value, 4);
            ptr += 11;
            i++;
        }

        rc = snprintf(paddrstr, 32, "%.16lx", paddr + i * 4);
        if (rc < 0 || rc >= 32) {
            errprint("Failed to properly format physical address\n");
            goto error;
        }
        ptr = strcasestr(ptr, paddrstr);
    }

    g_free(bufstr);
    g_free(paddrstr);
    return buf;

error:
    g_free(buf);
    g_free(bufstr);
    g_free(paddrstr);
    return NULL;
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

    struct request req;

    req.type = 2;   // write request
    req.address = (uint64_t) paddr;
    req.length = (uint64_t) length;

    int nbytes =
        write(kvm->socket_fd, &req,
              sizeof(struct request));
    if (nbytes != sizeof(struct request)) {
        goto error_exit;
    } else {
        uint8_t status = 0;

        if ( length != write(kvm->socket_fd, buf, length) )
            goto error_exit;

        if ( 1 != read(kvm->socket_fd, &status, 1) )
            goto error_exit;

        if (0 == status) {
            goto error_exit;
        }
    }

    /* Remove page from cache as cached contents are now stale */
    memory_cache_remove(vmi, paddr);

    return VMI_SUCCESS;
error_exit:
    return VMI_FAILURE;
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
    kvm_instance_t *kvm = kvm_get_instance(vmi);

    if (VMI_SUCCESS == test_using_kvm_patch(kvm)) {
        dbprint(VMI_DEBUG_KVM, "--kvm: resume custom patch for fast memory access\n");

        pid_cache_flush(vmi);
        sym_cache_flush(vmi);
        rva_cache_flush(vmi);
        v2p_cache_flush(vmi, ~0ull, 0);
        memory_cache_destroy(vmi);
        memory_cache_init(vmi, kvm_get_memory_patch, kvm_release_memory,
                          1);
        return VMI_SUCCESS;
    }

    char *status = exec_memory_access(kvm_get_instance(vmi));
    if (VMI_SUCCESS == exec_memory_access_success(status)) {
        dbprint(VMI_DEBUG_KVM, "--kvm: using custom patch for fast memory access\n");
        memory_cache_destroy(vmi);
        memory_cache_init(vmi, kvm_get_memory_patch, kvm_release_memory,
                          1);
        if (status)
            free(status);
        return init_domain_socket(kvm_get_instance(vmi));
    } else {
        dbprint
        (VMI_DEBUG_KVM, "--kvm: didn't find patch, falling back to slower native access\n");
        memory_cache_destroy(vmi);
        memory_cache_init(vmi, kvm_get_memory_native,
                          kvm_release_memory, 1);
        if (status)
            free(status);
        return VMI_SUCCESS;
    }
}

status_t
kvm_init(
    vmi_instance_t vmi,
    uint32_t UNUSED(init_flags),
    vmi_init_data_t* UNUSED(init_data))
{
    kvm_instance_t *kvm = g_try_malloc0(sizeof(kvm_instance_t));
    if (!kvm)
        return VMI_FAILURE;

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

status_t
kvm_init_vmi(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t* init_data)
{
    (void)init_flags; // unused
    (void)init_data; // unused

    kvm_instance_t *kvm = kvm_get_instance(vmi);
    virDomainInfo info;
    virDomainPtr dom = kvm->libvirt.virDomainLookupByID(kvm->conn, kvm->id);
    if (NULL == dom) {
        dbprint(VMI_DEBUG_KVM, "--failed to find kvm domain\n");
        return VMI_FAILURE;
    }

    // get the libvirt version
    unsigned long libVer = 0;

    if (kvm->libvirt.virConnectGetLibVersion(kvm->conn, &libVer) != 0) {
        dbprint(VMI_DEBUG_KVM, "--failed to get libvirt version\n");
        return VMI_FAILURE;
    }
    dbprint(VMI_DEBUG_KVM, "--libvirt version %lu\n", libVer);

    kvm->dom = dom;
    kvm->socket_fd = 0;
    vmi->vm_type = NORMAL;

    //get the VCPU count from virDomainInfo structure
    if (-1 == kvm->libvirt.virDomainGetInfo(kvm->dom, &info)) {
        dbprint(VMI_DEBUG_KVM, "--failed to get vm info\n");
        return VMI_FAILURE;
    }
    vmi->num_vcpus = info.nrVirtCpu;

# ifndef HAVE_LIBVMI_REQUEST
    struct json_object *qemu_version_obj = exec_info_version(kvm);
    dbprint(VMI_DEBUG_KVM, "--Checking QEMU version string...\n");
    // qemu_version JSON string :
    // {
    //   "return": {
    //     "qemu": {
    //       "micro": 0,
    //       "minor": 8,
    //       "major": 2
    //     },
    //     "package": ""
    //   },
    //   "id": "libvirt-42"
    // }

    struct json_object *return_obj= NULL;
    struct json_object *qemu_obj = NULL;
    struct json_object *major_obj = NULL;
    struct json_object *minor_obj = NULL;

    // get "return" object
    if (FALSE == json_object_object_get_ex(qemu_version_obj, "return", &return_obj))
        goto out_error;

    // get "qemu" object
    if (FALSE == json_object_object_get_ex(return_obj, "qemu", &qemu_obj))
        goto out_error;

    // get "major" object
    if (FALSE == json_object_object_get_ex(qemu_obj, "major", &major_obj))
        goto out_error;

    // get major int number
    int major = json_object_get_int(major_obj);

    // get "minor" object
    if (FALSE == json_object_object_get_ex(qemu_obj, "minor", &minor_obj))
        goto out_error;

    // get major int number
    int minor = json_object_get_int(minor_obj);
    // QEMU should be < 2.8.0
    if (major >= 2 && minor >= 8) {
        dbprint(VMI_DEBUG_KVM, "--Fail: incompatibility between libvmi and QEMU request definition detected\n");
        goto out_error;
    }
    goto success;
out_error:
    free(qemu_version_obj);
    free(return_obj);
    free(qemu_obj);
    free(major_obj);
    free(minor_obj);
    return VMI_FAILURE;
success:
    dbprint(VMI_DEBUG_KVM, "--SUCCESS\n");
# endif // !HAVE_LIBVMI_REQUEST

    return kvm_setup_live_mode(vmi);
}

void
kvm_destroy(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    if (!kvm) {
        return;
    }

    destroy_domain_socket(kvm);

    if (kvm->dom) {
        kvm->libvirt.virDomainFree(kvm->dom);
    }

    if (kvm->conn) {
        kvm->libvirt.virConnectClose(kvm->conn);
    }

    dlclose(kvm->libvirt.handle);
    g_free(kvm);

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
    virDomainInfo info;

    if (-1 == kvm->libvirt.virDomainGetInfo(kvm->dom, &info)) {
        dbprint(VMI_DEBUG_KVM, "--failed to get vm info\n");
        goto error_exit;
    }
    *allocated_ram_size = info.maxMem * 1024; // convert KBytes to bytes
    char *bufstr = exec_info_mtree(kvm_get_instance(vmi));
    addr_t parsed_max = parse_mtree(bufstr);

    if (parsed_max != 0)
        *maximum_physical_address = (addr_t) parsed_max;
    else
        *maximum_physical_address = *allocated_ram_size;

    return VMI_SUCCESS;
error_exit:
    return VMI_FAILURE;
}

status_t
kvm_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long UNUSED(vcpu))
{
    // TODO: vCPU specific registers
    char *regs = NULL;

    if (NULL == regs)
        regs = exec_info_registers(kvm_get_instance(vmi));

    status_t ret = VMI_SUCCESS;

    switch (reg) {
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
        case DR0:
            *value = parse_reg_value("DR0", regs);
            break;
        case DR1:
            *value = parse_reg_value("DR1", regs);
            break;
        case DR2:
            *value = parse_reg_value("DR2", regs);
            break;
        case DR3:
            *value = parse_reg_value("DR3", regs);
            break;
        case DR6:
            *value = parse_reg_value("DR6", regs);
            break;
        case DR7:
            *value = parse_reg_value("DR7", regs);
            break;
        case CS_SEL:
            *value = parse_seg_reg_value("CS", regs, SEGMENT_SELECTOR);
            break;
        case DS_SEL:
            *value = parse_seg_reg_value("DS", regs, SEGMENT_SELECTOR);
            break;
        case ES_SEL:
            *value = parse_seg_reg_value("ES", regs, SEGMENT_SELECTOR);
            break;
        case FS_SEL:
            *value = parse_seg_reg_value("FS", regs, SEGMENT_SELECTOR);
            break;
        case GS_SEL:
            *value = parse_seg_reg_value("GS", regs, SEGMENT_SELECTOR);
            break;
        case SS_SEL:
            *value = parse_seg_reg_value("SS", regs, SEGMENT_SELECTOR);
            break;
        case TR_SEL:
            *value = parse_seg_reg_value("TR", regs, SEGMENT_SELECTOR);
            break;
        case LDTR_SEL:
            *value = parse_seg_reg_value("LDT", regs, SEGMENT_SELECTOR);
            break;
        case CS_LIMIT:
            *value = parse_seg_reg_value("CS", regs, SEGMENT_LIMIT);
            break;
        case DS_LIMIT:
            *value = parse_seg_reg_value("DS", regs, SEGMENT_LIMIT);
            break;
        case ES_LIMIT:
            *value = parse_seg_reg_value("ES", regs, SEGMENT_LIMIT);
            break;
        case FS_LIMIT:
            *value = parse_seg_reg_value("FS", regs, SEGMENT_LIMIT);
            break;
        case GS_LIMIT:
            *value = parse_seg_reg_value("GS", regs, SEGMENT_LIMIT);
            break;
        case SS_LIMIT:
            *value = parse_seg_reg_value("SS", regs, SEGMENT_LIMIT);
            break;
        case TR_LIMIT:
            *value = parse_seg_reg_value("TR", regs, SEGMENT_LIMIT);
            break;
        case LDTR_LIMIT:
            *value = parse_seg_reg_value("LDTR", regs, SEGMENT_LIMIT);
            break;
        case IDTR_LIMIT:
            *value = parse_seg_reg_value("IDTR", regs, SEGMENT_LIMIT);
            break;
        case GDTR_LIMIT:
            *value = parse_seg_reg_value("GDTR", regs, SEGMENT_LIMIT);
            break;
        case CS_BASE:
            *value = parse_seg_reg_value("CS", regs, SEGMENT_BASE);
            break;
        case DS_BASE:
            *value = parse_seg_reg_value("DS", regs, SEGMENT_BASE);
            break;
        case ES_BASE:
            *value = parse_seg_reg_value("ES", regs, SEGMENT_BASE);
            break;
        case FS_BASE:
            *value = parse_seg_reg_value("FS", regs, SEGMENT_BASE);
            break;
        case GS_BASE:
            *value = parse_seg_reg_value("GS", regs, SEGMENT_BASE);
            break;
        case SS_BASE:
            *value = parse_seg_reg_value("SS", regs, SEGMENT_BASE);
            break;
        case TR_BASE:
            *value = parse_seg_reg_value("TR", regs, SEGMENT_BASE);
            break;
        case LDTR_BASE:
            *value = parse_seg_reg_value("LDT", regs, SEGMENT_BASE);
            break;
        case IDTR_BASE:
            *value = parse_seg_reg_value("IDT", regs, SEGMENT_BASE);
            break;
        case GDTR_BASE:
            *value = parse_seg_reg_value("GDT", regs, SEGMENT_BASE);
            break;
        case CS_ARBYTES:
            *value = parse_seg_reg_value("CS", regs, SEGMENT_ATTR);
            break;
        case DS_ARBYTES:
            *value = parse_seg_reg_value("DS", regs, SEGMENT_ATTR);
            break;
        case ES_ARBYTES:
            *value = parse_seg_reg_value("ES", regs, SEGMENT_ATTR);
            break;
        case FS_ARBYTES:
            *value = parse_seg_reg_value("FS", regs, SEGMENT_ATTR);
            break;
        case GS_ARBYTES:
            *value = parse_seg_reg_value("GS", regs, SEGMENT_ATTR);
            break;
        case SS_ARBYTES:
            *value = parse_seg_reg_value("SS", regs, SEGMENT_ATTR);
            break;
        case TR_ARBYTES:
            *value = parse_seg_reg_value("TR", regs, SEGMENT_ATTR);
            break;
        case LDTR_ARBYTES:
            *value = parse_seg_reg_value("LDT", regs, SEGMENT_ATTR);
            break;
        case MSR_EFER:
            *value = parse_reg_value("EFER", regs);
            break;
        default:
            if ( VMI_PM_IA32E == vmi->page_mode) {
                switch (reg) {
                    case RAX:
                        *value = parse_reg_value("RAX", regs);
                        break;
                    case RBX:
                        *value = parse_reg_value("RBX", regs);
                        break;
                    case RCX:
                        *value = parse_reg_value("RCX", regs);
                        break;
                    case RDX:
                        *value = parse_reg_value("RDX", regs);
                        break;
                    case RBP:
                        *value = parse_reg_value("RBP", regs);
                        break;
                    case RSI:
                        *value = parse_reg_value("RSI", regs);
                        break;
                    case RDI:
                        *value = parse_reg_value("RDI", regs);
                        break;
                    case RSP:
                        *value = parse_reg_value("RSP", regs);
                        break;
                    case R8:
                        *value = parse_reg_value("R8", regs);
                        break;
                    case R9:
                        *value = parse_reg_value("R9", regs);
                        break;
                    case R10:
                        *value = parse_reg_value("R10", regs);
                        break;
                    case R11:
                        *value = parse_reg_value("R11", regs);
                        break;
                    case R12:
                        *value = parse_reg_value("R12", regs);
                        break;
                    case R13:
                        *value = parse_reg_value("R13", regs);
                        break;
                    case R14:
                        *value = parse_reg_value("R14", regs);
                        break;
                    case R15:
                        *value = parse_reg_value("R15", regs);
                        break;
                    case RIP:
                        *value = parse_reg_value("RIP", regs);
                        break;
                    case RFLAGS:
                        *value = parse_reg_value("RFL", regs);
                        break;
                    default:
                        ret = VMI_FAILURE;
                        break;
                }
            } else {
                switch (reg) {
                    case RAX:
                        *value = parse_reg_value("EAX", regs);
                        break;
                    case RBX:
                        *value = parse_reg_value("EBX", regs);
                        break;
                    case RCX:
                        *value = parse_reg_value("ECX", regs);
                        break;
                    case RDX:
                        *value = parse_reg_value("EDX", regs);
                        break;
                    case RBP:
                        *value = parse_reg_value("EBP", regs);
                        break;
                    case RSI:
                        *value = parse_reg_value("ESI", regs);
                        break;
                    case RDI:
                        *value = parse_reg_value("EDI", regs);
                        break;
                    case RSP:
                        *value = parse_reg_value("ESP", regs);
                        break;
                    case RIP:
                        *value = parse_reg_value("EIP", regs);
                        break;
                    case RFLAGS:
                        *value = parse_reg_value("EFL", regs);
                        break;
                    default:
                        ret = VMI_FAILURE;
                        break;
                }
            }

            break;
    }

    if (regs)
        free(regs);
    return ret;

    return VMI_FAILURE;
}

status_t
kvm_pause_vm(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    if (-1 == kvm->libvirt.virDomainSuspend(kvm->dom)) {
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

status_t
kvm_resume_vm(
    vmi_instance_t vmi)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);
    if (-1 == kvm->libvirt.virDomainResume(kvm->dom)) {
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

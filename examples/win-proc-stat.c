/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Sergey Kovalev (valor@list.ru)
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

#include <glib.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/events.h>
#include <json-c/json.h>

/* Structure to pass data into event callback */
struct cb_context {
    addr_t* offsets;
    GHashTable* stats;
};

/*
 * Structures and functions to store stat data
 */
typedef union pid_tid {
    struct {
        uint64_t pid : 32;
        uint64_t tid : 32;
    };
    uint64_t value;
} pid_tid_t;

guint pid_tid_hash(gconstpointer key)
{
    pid_tid_t k = { .value = (uint64_t)key };
    uint32_t hash = (k.pid & 0xffff) + (k.tid << 16);

    return hash;
};

int pid_tid_cmp(const void* a, const void* b)
{
    pid_tid_t a_ = { .value = (uint64_t)a };
    pid_tid_t b_ = { .value = (uint64_t)b };

    bool rc = 0;
    if (a_.pid == b_.pid && a_.tid == b_.tid)
        rc = 1;

    return rc;
}

void print_stats(gpointer key, gpointer value, __attribute__((unused)) gpointer userdata)
{
    pid_tid_t k = { .value = (uint64_t)key };
    uint64_t v = (uint64_t)value;

    printf("PID:%d,TID:%d,COUNT:%ld\n", k.pid, k.tid, v);
}

/*
 * Map offset enums to actual structure+member or global variable/function names.
 */
enum win_offsets {
    KPCR_PRCB,
    KPCR_PRCBDATA,
    KPRCB_CURRENTTHREAD,
    ETHREAD_CID,
    CLIENT_ID_UNIQUETHREAD,
    __WIN_OFFSETS_MAX
};

static const char* win_offset_names[__WIN_OFFSETS_MAX][2] = {
    [KPCR_PRCB] = {"_KPCR", "Prcb" },
    [KPCR_PRCBDATA] = {"_KPCR", "PrcbData" },
    [KPRCB_CURRENTTHREAD] = { "_KPRCB", "CurrentThread" },
    [ETHREAD_CID] = {"_ETHREAD", "Cid" },
    [CLIENT_ID_UNIQUETHREAD] = {"_CLIENT_ID", "UniqueThread" },
};

static bool profile_lookup_array(
    vmi_instance_t vmi,
    json_object* profile_json,
    const char* symbol_subsymbol_array[][2],
    addr_t array_size,
    addr_t* rva)
{
    bool ret = false;

    if (!profile_json) {
        fprintf(stderr, "Rekall profile json is NULL!\n");
        return ret;
    }

    int errors = 0;
    for (size_t i = 0; i < array_size; i++) {
        if (VMI_SUCCESS != vmi_get_struct_member_offset_from_json(
                    vmi,
                    profile_json,
                    symbol_subsymbol_array[i][0],
                    symbol_subsymbol_array[i][1],
                    &rva[i])
           ) {
            errors++;
            printf("Failed to find offset for %s:%s\n",
                   symbol_subsymbol_array[i][0], symbol_subsymbol_array[i][1]);
        }
    }

    if (errors == 0)
        ret = true;

    return ret;
}

static addr_t* fill_offsets_from_profile(vmi_instance_t vmi, const char* profile)
{
    addr_t* offsets = (addr_t*)g_malloc0(sizeof(addr_t) * __WIN_OFFSETS_MAX );
    if ( !offsets )
        return NULL;

    json_object* profile_json = json_object_from_file(profile);
    if (!profile_lookup_array(
                vmi,
                profile_json,
                win_offset_names,
                __WIN_OFFSETS_MAX,
                offsets))
        printf("Failed to find offsets for array of structure names and subsymbols.\n");

    return offsets;
}

static int32_t get_current_thread_id(vmi_instance_t vmi, vmi_event_t* event)
{
    x86_registers_t* regs = event->x86_regs;
    addr_t* offsets = ((struct cb_context*)event->data)->offsets;

    addr_t thread = 0;
    addr_t prcb = 0;
    addr_t kpcr = 0;
    uint64_t ss_arbytes = regs->ss_arbytes;

    // TODO This for Xen 4.8-4.11 only
    if (!ss_arbytes && VMI_FAILURE == vmi_get_vcpureg(vmi, &ss_arbytes, SS_ARBYTES, event->vcpu_id))
        return -1;

    // From Intel SDM (325462-067US), Volume 3, 24.4.1:
    // The value of the DPL field for SS is always equal to the logical processor’s current privilege level (CPL).
    unsigned int cpl = (ss_arbytes >> 5) & 3;

    page_mode_t page_mode = vmi_get_page_mode(vmi, event->vcpu_id);
    if (VMI_PM_IA32E == page_mode) {
        prcb = offsets[KPCR_PRCB];
        if ( cpl ) {
            // TODO: Xen 4.13 will have the correct value in the regs->shadow_gs
            if (VMI_FAILURE == vmi_get_vcpureg(vmi, &kpcr, SHADOW_GS, event->vcpu_id))
                return -1;
        } else
            kpcr = regs->gs_base;
    } else if (VMI_PM_PAE == page_mode || VMI_PM_LEGACY == page_mode) {
        /*
         * "In 32-bit Windows, entering kernel mode gets fs loaded with a GDT selector (0x0030)
         * for a segment whose base address is that of the processor’s KPCR."
         * https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kpcr.htm
         * https://wiki.osdev.org/Global_Descriptor_Table
         */
        if ( cpl ) {
            addr_t gdt;

            // TODO: Xen 4.13 will have the value delivered in the regs->gdtr_base
            if (VMI_FAILURE == vmi_get_vcpureg(vmi, &gdt, GDTR_BASE, event->vcpu_id))
                return -1;

            uint16_t fs_low = 0;
            uint8_t fs_mid = 0, fs_high = 0;

            if (VMI_FAILURE == vmi_read_16_va(vmi, gdt + 0x32, 0, &fs_low))
                return -1;
            if (VMI_FAILURE == vmi_read_8_va(vmi, gdt + 0x34, 0, &fs_mid))
                return -1;
            if (VMI_FAILURE == vmi_read_8_va(vmi, gdt + 0x37, 0, &fs_high))
                return -1;

            kpcr = ((uint32_t)fs_low) | ((uint32_t)fs_mid) << 16 | ((uint32_t)fs_high) << 24;
        } else
            kpcr = regs->fs_base;

        prcb = offsets[KPCR_PRCBDATA];
    }

    if (VMI_SUCCESS != vmi_read_addr_va(vmi, kpcr + prcb + offsets[KPRCB_CURRENTTHREAD], 0, &thread)) {
        return -1;
    }

    addr_t tid = -1;
    if ( vmi_read_addr_va( vmi, thread + offsets[ ETHREAD_CID ] + offsets[ CLIENT_ID_UNIQUETHREAD ],
                           0,
                           &tid ) == VMI_SUCCESS )
        return tid;

    return -1;
}

static event_response_t cr3_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    if (!event->data) {
        printf("Null pointer to context!\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    GHashTable* stats = ((struct cb_context*)event->data)->stats;

    vmi_pid_t pid = -1;
    vmi_dtb_to_pid(vmi, event->reg_event.value, &pid);
    int32_t tid = get_current_thread_id(vmi, event);

    if (pid >= 0 && tid >= 0) {
        pid_tid_t key = { .pid = pid, .tid = tid };
        uint64_t value = (uint64_t)g_hash_table_lookup(stats, (gpointer)key.value) + 1;
        g_hash_table_insert(stats, (gpointer)key.value, (gpointer)value);
    } else
        printf("Failed to get PID (%i) or TID (%i)\n", pid, tid);

    return VMI_EVENT_RESPONSE_NONE;
}

static volatile int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

int main(int argc, char** argv)
{
    /* this is the VM that we are looking at */
    if (argc != 5) {
        printf("Usage: %s name|domid <domain name|domain id> -r <profile>\n", argv[0]);
        return 1;
    }

    void* domain;
    uint64_t domid = VMI_INVALID_DOMID;
    uint64_t init_flags =  VMI_INIT_EVENTS;

    if (strcmp(argv[1], "name")==0) {
        domain = (void*)argv[2];
        init_flags |= VMI_INIT_DOMAINNAME;
    } else if (strcmp(argv[1], "domid")==0) {
        domid = strtoull(argv[2], NULL, 0);
        domain = (void*)&domid;
        init_flags |= VMI_INIT_DOMAINID;
    } else {
        printf("You have to specify either name or domid!\n");
        return 1;
    }

    char* profile = NULL;

    if (strcmp(argv[3], "-r") == 0) {
        profile = argv[4];
    } else {
        printf("You have to specify path to profile!\n");
        return 1;
    }

    /* for a clean exit */
    struct sigaction act;

    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* Some local variables */
    struct cb_context* ctx = NULL;
    GHashTable* stats = NULL;

    /* initialize the libvmi library */
    vmi_instance_t vmi = NULL;
    vmi_init_error_t err = VMI_SUCCESS;

    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, domain, init_flags, NULL,
                              VMI_CONFIG_JSON_PATH, profile, &err)) {
        printf("Failed to init LibVMI library: %d.\n", err);
        goto done;
    }

    /* Get offsets */
    addr_t* offsets = fill_offsets_from_profile(vmi, profile);
    if (!offsets)
        return 1;

    /*
     * Prepare event
     */
    stats = g_hash_table_new_full(pid_tid_hash, pid_tid_cmp, NULL, NULL);
    if (!stats) {
        printf("Failed to create GHashTable!\n");
        goto done;
    }

    ctx = (struct cb_context*)g_malloc0(sizeof(struct cb_context));
    if (!ctx) {
        printf("Failed to allocate memory for context!\n");
        goto done;
    }
    ctx->offsets = offsets;
    ctx->stats = stats;

    vmi_event_t cr3_event;

    memset(&cr3_event, 0, sizeof(vmi_event_t));
    cr3_event.version = VMI_EVENTS_VERSION;
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.callback = cr3_cb;
    cr3_event.data = ctx;

    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;

    if ( VMI_FAILURE == vmi_register_event(vmi, &cr3_event) ) {
        printf("Failed to register CR3 event\n");
        goto done;
    }

    while (!interrupted) {
        if (vmi_events_listen(vmi, 500) != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }

    vmi_pause_vm(vmi);

    // Process any events that may have been left
    if ( vmi_are_events_pending(vmi) > 0 )
        vmi_events_listen(vmi, 0);

    vmi_clear_event(vmi, &cr3_event, NULL);

    vmi_resume_vm(vmi);

    g_hash_table_foreach(stats, print_stats, NULL);

done:
    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    if (stats)
        g_hash_table_destroy(stats);

    if (offsets)
        g_free(offsets);

    if (ctx)
        g_free(ctx);

    return 0;
}

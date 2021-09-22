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

#define _GNU_SOURCE

#define LIBVMI_EXTRA_JSON

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <libvmi/events.h>
#include <libvmi/libvmi_extra.h>
#include <json-c/json.h>

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>
#include <glib.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

vmi_instance_t vmi;
vmi_init_data_t *init_data;
GHashTable* config;
vmi_event_t cr3_event;

int find_pid4_success = 0;
uint64_t found_cr3;

addr_t offset_kpcr_prcb;
addr_t offset_kprcb_currentthread;
addr_t offset_eprocess_uniqueprocessid;
addr_t offset_kthread_process;

int enable_debug = 0;

void dp(const char* format, ...)
{
    va_list argptr;
    va_start(argptr, format);

    if (enable_debug)
        vfprintf(stderr, format, argptr);

    va_end(argptr);
}

void clean_up(void)
{
    vmi_destroy(vmi);
    if (config)
        g_hash_table_destroy(config);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }
}

void sigint_handler()
{
    clean_up();
    exit(1);
}

event_response_t cr3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    dp("CR#: %llx, VCPU: %u\n", event->reg_event.value, event->vcpu_id);

    if (find_pid4_success) {
        dp("Skip callback as we already found System process\n");
        goto failed;
    }

    addr_t gs_base;
    addr_t kthread;
    addr_t eprocess;

    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_DTB,
                   .dtb = event->reg_event.value);

    /*
     * Get current GS_BASE and translate its VA to PA using current CR3.
     * This may fail (most probably) if we are in user-mode DTB with KPTI hardening.
     */
    page_mode_t pm = vmi_get_page_mode(vmi, 0);
    gs_base = ( pm == VMI_PM_IA32E ? event->x86_regs->gs_base : event->x86_regs->fs_base );

    /*
     * Inspect _KPCR to find _KTHREAD of currently running thread.
     */
    addr_t prcb = gs_base + offset_kpcr_prcb;
    addr_t cur_thread = prcb + offset_kprcb_currentthread;
    addr_t pid;

    ctx.addr = cur_thread;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &kthread)) {
        dp("Failed to get current KTHREAD from GS_BASE\n");
        goto failed;
    }

    /*
     * Find _EPROCESS of currently running thread.
     */
    addr_t pkprocess = kthread + offset_kthread_process;

    ctx.addr = pkprocess;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &eprocess)) {
        dp("Failed to get EPROCESS from KTHREAD\n");
        goto failed;
    }

    /*
     * Find PID of currently running process.
     */
    addr_t pid_ptr = eprocess + offset_eprocess_uniqueprocessid;

    ctx.addr = pid_ptr;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &pid)) {
        dp("Failed to get PID from EPROCESS\n");
        goto failed;
    }

    /*
     * Check if we've caught System process. This would ensure that
     * current DTB for VCPU=0 contains all necessary kernel mappings.
     * These mappings may not be present or be incomplete in other processes
     * due to KPTI.
     */
    if (pid != 4) {
        dp("Current PID=%llx, skip until we reach PID=4\n", (unsigned long long)pid);
        goto failed;
    }

    dp("Stopped inside system process, VCPU %u, CR3=%llx\n", event->vcpu_id, event->reg_event.value);
    find_pid4_success = 1;
    found_cr3 = event->reg_event.value;

    /*
     * Remove CR3 event and leave the VM paused inside System process,
     * to make it easy for LibVMI to detect all necessary offsets.
     */
    dp("Cleared event\n");
    vmi_pause_vm(vmi);
    vmi_clear_event(vmi, event, NULL);
    return VMI_EVENT_RESPONSE_NONE;

failed:
    return VMI_EVENT_RESPONSE_NONE;
}

void show_usage(char *arg0)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s [OPTIONS...]\n", arg0);
    fprintf(stderr, "\n");
    fprintf(stderr, "Required one of:\n");
    fprintf(stderr, "    -n, --name           Domain name\n");
    fprintf(stderr, "    -d, --domid          Domain ID\n");
    fprintf(stderr, "Required input:\n");
    fprintf(stderr, "    -r, --json-kernel    The OS kernel's json profile\n");
    fprintf(stderr, "Optional input:\n");
    fprintf(stderr, "    -v, --verbose        Enable verbose mode\n");
    fprintf(stderr, "    -k, --only-kpgd      Only print KPGD value\n");
    fprintf(stderr, "    -s, --kvmi-socket    Specify KVMi socket for KVM driver\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "    %s -n win7vm -r /opt/kernel.json\n", arg0);
    fprintf(stderr, "    %s --domid 17 --json-kernel /opt/kernel.json --only-kpgd\n", arg0);
}

int main(int argc, char **argv)
{
    vmi_mode_t mode;
    int rc = 1;

    void *domain = NULL;
    uint64_t domid = VMI_INVALID_DOMID;
    uint64_t init_flags = 0;
    int only_output_kpgd = 0;

    char *kernel_profile = NULL;
    int long_index = 0;
    char c;

    const struct option long_opts[] = {
        {"name", required_argument, NULL, 'n'},
        {"domid", required_argument, NULL, 'd'},
        {"json-kernel", required_argument, NULL, 'r'},
        {"verbose", no_argument, NULL, 'v'},
        {"only-kpgd", no_argument, NULL, 'k'},
        {"kvmi-socket", required_argument, NULL, 's'},
    };

    while ((c = getopt_long (argc, argv, "n:d:kvr:s:", long_opts, &long_index)) != -1)
        switch (c) {
            case 'n':
                domain = (void *)optarg;
                init_flags |= VMI_INIT_DOMAINNAME;
                break;
            case 'd':
                domid = strtoull(optarg, NULL, 0);
                domain = (void *)&domid;
                init_flags |= VMI_INIT_DOMAINID;
                break;
            case 'k':
                only_output_kpgd = 1;
                break;
            case 'v':
                enable_debug = 1;
                break;
            case 'r':
                kernel_profile = optarg;
                break;
            case 's':
                init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
                init_data->count = 1;
                init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
                init_data->entry[0].data = strdup(optarg);
                break;
            default:
                show_usage(argv[0]);
                return 1;
        }

    if (optind != argc) {
        fprintf(stderr, "Unrecognized argument: %s\n", argv[optind]);
        show_usage(argv[0]);
        return 1;
    }

    if (!domain) {
        fprintf(stderr, "You have to specify --name or --domid!\n");
        show_usage(argv[0]);
        return 1;
    }

    if ((init_flags & VMI_INIT_DOMAINNAME) && (init_flags & VMI_INIT_DOMAINID)) {
        fprintf(stderr, "Both domain ID and domain name provided!\n");
        show_usage(argv[0]);
        return 1;
    }

    if (!kernel_profile) {
        fprintf(stderr, "You have to specify path to kernel JSON profile!\n");
        show_usage(argv[0]);
        return 1;
    }

    if (VMI_FAILURE == vmi_get_access_mode(vmi, domain, init_flags, init_data, &mode)) {
        printf("Failed to get access mode\n");
        goto done;
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, domain, init_flags | VMI_INIT_EVENTS, init_data, NULL)) {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        goto done;
    }

    signal(SIGINT, sigint_handler);

    config = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    if (!config) {
        fprintf(stderr, "Failed to create GHashTable!\n");
        goto done;
    }

    g_hash_table_insert(config, g_strdup("os_type"), g_strdup("Windows"));
    g_hash_table_insert(config, g_strdup("rekall_profile"), g_strdup(kernel_profile));

    if (VMI_PM_UNKNOWN == vmi_init_paging(vmi, VMI_PM_INITFLAG_TRANSITION_PAGES) ) {
        fprintf(stderr, "Failed to init LibVMI paging.\n");
        goto done;
    }

    os_t os = vmi_init_profile(vmi, VMI_CONFIG_GHASHTABLE, config);
    if (VMI_OS_WINDOWS != os) {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        goto done;
    }

    g_hash_table_remove(config, "rekall_profile");
    json_object* profile = vmi_get_kernel_json(vmi);

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_KPCR", "PrcbData", &offset_kpcr_prcb)) {
        // PrcbData was renamed to Prcb in 64-bit Windows
        if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_KPCR", "Prcb", &offset_kpcr_prcb)) {
            fprintf(stderr, "Failed to find _KPCR->Prcb member offset\n");
            goto done;
        }
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_KPRCB", "CurrentThread", &offset_kprcb_currentthread)) {
        fprintf(stderr, "Failed to find _KPRCB->CurrentThread member offset\n");
        goto done;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_EPROCESS", "UniqueProcessId", &offset_eprocess_uniqueprocessid)) {
        fprintf(stderr, "Failed to find _EPROCESS->UniqueProcessId member offset\n");
        goto done;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_KTHREAD", "Process", &offset_kthread_process)) {
        fprintf(stderr, "Failed to find _KTHREAD->Process member offset\n");
        goto done;
    }

    memset(&cr3_event, 0, sizeof(vmi_event_t));
    cr3_event.version = VMI_EVENTS_VERSION;
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;
    cr3_event.callback = cr3_cb;

    if (VMI_FAILURE == vmi_register_event(vmi, &cr3_event)) {
        fprintf(stderr, "Failed to register CR3 write event\n");
        goto done;
    }

    while (!find_pid4_success) {
        if (VMI_FAILURE == vmi_events_listen(vmi, 500)) {
            fprintf(stderr, "Failed to listen to VMI events\n");
            goto done;
        }
    }

    if ( vmi_are_events_pending(vmi) > 0 )
        vmi_events_listen(vmi, 0);

    uint64_t *val_cr3 = (uint64_t*)g_malloc(sizeof(uint64_t));
    *val_cr3 = found_cr3;
    g_hash_table_insert(config, g_strdup("kpgd"), val_cr3);

    // the vm is already paused if we've got here
    os = vmi_init_os(vmi, VMI_CONFIG_GHASHTABLE, config, NULL);
    if (VMI_OS_WINDOWS != os) {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        goto done;
    }

    /* Get internal fields */
    addr_t ntoskrnl = 0;
    addr_t ntoskrnl_va = 0;
    addr_t tasks = 0;
    addr_t pdbase = 0;
    addr_t pid = 0;
    addr_t pname = 0;
    addr_t kdvb = 0;
    addr_t sysproc = 0;
    addr_t kpcr = 0;
    addr_t kdbg = 0;
    addr_t kpgd = 0;

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_ntoskrnl", &ntoskrnl))
        fprintf(stderr, "Failed to read field \"ntoskrnl\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_ntoskrnl_va", &ntoskrnl_va))
        fprintf(stderr, "Failed to read field \"ntoskrnl_va\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks))
        fprintf(stderr, "Failed to read field \"tasks\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_pdbase", &pdbase))
        fprintf(stderr, "Failed to read field \"pdbase\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_pid", &pid))
        fprintf(stderr, "Failed to read field \"pid\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_pname", &pname))
        fprintf(stderr, "Failed to read field \"pname\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_kdvb", &kdvb))
        fprintf(stderr, "Failed to read field \"kdvb\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_sysproc", &sysproc))
        fprintf(stderr, "Failed to read field \"sysproc\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_kpcr", &kpcr))
        fprintf(stderr, "Failed to read field \"kpcr\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_kdbg", &kdbg))
        fprintf(stderr, "Failed to read field \"kdbg\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "kpgd", &kpgd))
        fprintf(stderr, "Failed to read field \"kpgd\"\n");

    if (only_output_kpgd) {
        printf("0x%lx", kpgd);
    } else {
        printf("win_ntoskrnl:0x%lx\n"
               "win_ntoskrnl_va:0x%lx\n"
               "win_tasks:0x%lx\n"
               "win_pdbase:0x%lx\n"
               "win_pid:0x%lx\n"
               "win_pname:0x%lx\n"
               "win_kdvb:0x%lx\n"
               "win_sysproc:0x%lx\n"
               "win_kpcr:0x%lx\n"
               "win_kdbg:0x%lx\n"
               "kpgd:0x%lx\n",
               ntoskrnl,
               ntoskrnl_va,
               tasks,
               pdbase,
               pid,
               pname,
               kdvb,
               sysproc,
               kpcr,
               kdbg,
               kpgd);
    }

    if (!ntoskrnl || !ntoskrnl_va || !sysproc || !pdbase || !kpgd) {
        fprintf(stderr, "Failed to get most essential fields\n");
        goto done;
    }

    vmi_resume_vm(vmi);

    rc = 0;

done:
    clean_up();

    return rc;
}

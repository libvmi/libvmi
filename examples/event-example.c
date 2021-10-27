/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Nasser Salim (njsalim@sandia.gov)
 * Author: Steven Maresca (steve@zentific.com)
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#define PAGE_SIZE 1 << 12

reg_t cr3;
reg_t lstar;
reg_t sysenter_ip;
vmi_event_t cr3_event;
vmi_event_t msr_syscall_lm_event;
vmi_event_t msr_syscall_sysenter_event;
vmi_event_t kernel_vsyscall_event;
bool mem_events_registered;

/*
 * Per Linux ABI, this VA represents the start of the vsyscall page
 *  If vsyscall support is enabled (deprecated or disabled on many newer
 *  3.0+ kernels), it is accessible at this address in every process.
 */
addr_t vsyscall = 0xffffffffff600000;

void print_event(vmi_event_t event)
{
    printf("PAGE ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %"PRIu32")\n",
           (event.mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
           (event.mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
           (event.mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
           event.mem_event.gfn,
           event.mem_event.offset,
           event.mem_event.gla,
           event.vcpu_id
          );
}


/* MSR registers used to hold system calls in x86_64. Note that compat mode is
 *  used in concert with long mode for certain system calls.
 *  e.g. in 3.2.0 ioctl, getrlimit, etc. (see /usr/include/asm-generic/unistd.h)
 * MSR_STAR     -    legacy mode SYSCALL target (not addressed here)
 * MSR_CSTAR    -    compat mode SYSCALL target (not addressed here)
 * MSR_LSTAR    -    long mode SYSCALL target
 *
 * Note that modern code tends to employ the sysenter and/or vDSO mechanisms for
 *    performance reasons.
 */

event_response_t msr_syscall_sysenter_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    print_event(*event);

    if ( event->x86_regs->rip != sysenter_ip ) {
        vmi_clear_event(vmi, event, NULL);
        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
        return 0;
    }

    reg_t rdi, rax;

    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("SYSENTER_IP Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n",
           (unsigned int)rax, (unsigned int)rdi);

    vmi_clear_event(vmi, event, NULL);
    return 0;
}

event_response_t vsyscall_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    print_event(*event);

    if ( event->x86_regs->rip != vsyscall ) {
        vmi_clear_event(vmi, event, NULL);
        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
        return 0;
    }

    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("VSYSCALL Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    vmi_clear_event(vmi, event, NULL);
    return 0;
}

event_response_t syscall_lm_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    print_event(*event);

    if ( event->mem_event.offset != (VMI_BIT_MASK(0,11) & lstar) ) {
        vmi_clear_event(vmi, event, NULL);
        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
        return 0;
    }

    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("LSTAR Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    vmi_clear_event(vmi, event, NULL);
    return 0;
}

bool register_mem_events(vmi_instance_t vmi, vmi_event_t *event)
{
    // use cr3 value that's being loaded
    addr_t cr3 = event->reg_event.value;
    addr_t phys_lstar = 0;
    addr_t phys_sysenter_ip = 0;
    bool ret = false;
    addr_t phys_vsyscall = 0;

    // Get the value of lstar for the system.
    // NOTE: all vCPUs have the same value for this register
    lstar = event->x86_regs->msr_lstar;
    vmi_get_vcpureg(vmi, &sysenter_ip, SYSENTER_EIP, 0);
    printf("vcpu %u MSR_LSTAR == %llx\n", event->vcpu_id, (unsigned long long)lstar);
    printf("vcpu %u MSR_SYSENTER_IP == %llx\n", event->vcpu_id, (unsigned long long)sysenter_ip);

    // Translate to a physical address.
    vmi_pagetable_lookup(vmi, event->x86_regs->cr3, lstar, &phys_lstar);
    printf("Physical LSTAR == %llx\n", (unsigned long long)phys_lstar);

    vmi_pagetable_lookup(vmi, event->x86_regs->cr3, sysenter_ip, &phys_sysenter_ip);
    printf("Physical SYSENTER_IP == %llx\n", (unsigned long long)phys_sysenter_ip);

    // Get only the page that the handler starts.
    printf("LSTAR Physical PFN == %llx\n", (unsigned long long)(phys_lstar >> 12));
    printf("SYSENTER_IP Physical PFN == %llx\n", (unsigned long long)(phys_sysenter_ip >> 12));
    printf("phys_vsyscall Physical PFN == %llx\n", (unsigned long long)(phys_vsyscall >> 12));

    // Setup a default event for tracking memory at the syscall handler.
    msr_syscall_sysenter_event.version = VMI_EVENTS_VERSION;
    msr_syscall_sysenter_event.type = VMI_EVENT_MEMORY;
    msr_syscall_sysenter_event.mem_event.gfn = phys_sysenter_ip >> 12;
    msr_syscall_sysenter_event.mem_event.in_access = VMI_MEMACCESS_X;
    msr_syscall_sysenter_event.callback=msr_syscall_sysenter_cb;

    msr_syscall_lm_event.version = VMI_EVENTS_VERSION;
    msr_syscall_lm_event.type = VMI_EVENT_MEMORY;
    msr_syscall_lm_event.mem_event.gfn = phys_lstar >> 12;
    msr_syscall_lm_event.mem_event.in_access = VMI_MEMACCESS_X;
    msr_syscall_lm_event.callback=syscall_lm_cb;

    kernel_vsyscall_event.version = VMI_EVENTS_VERSION;
    kernel_vsyscall_event.type = VMI_EVENT_MEMORY;
    kernel_vsyscall_event.mem_event.gfn = phys_vsyscall >> 12;
    kernel_vsyscall_event.mem_event.in_access = VMI_MEMACCESS_X;
    kernel_vsyscall_event.callback=vsyscall_cb;

    if ( phys_sysenter_ip && VMI_SUCCESS == vmi_register_event(vmi, &msr_syscall_sysenter_event) )
        ret = true;
    else
        printf("Failed to register memory event on MSR_SYSENTER_IP page\n");

    if ( phys_lstar && VMI_SUCCESS == vmi_register_event(vmi, &msr_syscall_lm_event) )
        ret = true;
    else
        printf("Failed to register memory event on MSR_LSTAR page\n");

    if ( phys_vsyscall && VMI_SUCCESS == vmi_register_event(vmi, &kernel_vsyscall_event) )
        ret = true;
    else
        printf("Failed to register memory event on vsyscall page\n");

    return ret;
}

event_response_t cr3_all_tasks_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    printf("CR3=%"PRIx64" executing on vcpu %"PRIu32". Previous CR3=%"PRIx64"\n",
           event->reg_event.value, event->vcpu_id, event->reg_event.previous);

    if ( !mem_events_registered )
        mem_events_registered = register_mem_events(vmi, event);

    return 0;
}

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = NULL;
    status_t status = VMI_SUCCESS;
    struct sigaction act;
    char *name = NULL;
    vmi_init_data_t *init_data = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name of VM> [<socket>]\n", argv[0]);
        exit(1);
    }

    // Arg 1 is the VM name.
    name = argv[1];

    if (argc == 3) {
        char *path = argv[2];

        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    vmi_mode_t mode;
    if (VMI_FAILURE == vmi_get_access_mode(NULL, name, VMI_INIT_DOMAINNAME, init_data, &mode)) {
        printf("Failed to find a supported hypervisor with LibVMI\n");
        return 1;
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    if ( VMI_PM_UNKNOWN == vmi_init_paging(vmi, 0) ) {
        printf("Failed to init determine paging.\n");
        vmi_destroy(vmi);
        return 1;
    }

    printf("LibVMI init succeeded!\n");

    /* Configure an event to track when the process is running.
     * (The CR3 register is updated on task context switch, allowing
     *  us to follow as various tasks are scheduled and run upon the CPU)
     */
    memset(&cr3_event, 0, sizeof(vmi_event_t));
    cr3_event.version = VMI_EVENTS_VERSION;
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.callback = cr3_all_tasks_callback;

    /* Observe only write events to the given register.
     *   NOTE: read events are unsupported at this time.
     */
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;

    if ( VMI_SUCCESS == vmi_register_event(vmi, &cr3_event) ) {
        while (!interrupted) {
            printf("Waiting for events...\n");
            status = vmi_events_listen(vmi,500);
            if (status != VMI_SUCCESS) {
                printf("Error waiting for events, quitting...\n");
                interrupted = -1;
            }
        }
    }

    vmi_pause_vm(vmi);

    // Process any events that may have been left
    if ( vmi_are_events_pending(vmi) > 0 )
        vmi_events_listen(vmi, 0);

    vmi_clear_event(vmi, &cr3_event, NULL);
    vmi_clear_event(vmi, &msr_syscall_lm_event, NULL);
    vmi_clear_event(vmi, &msr_syscall_sysenter_event, NULL);
    vmi_clear_event(vmi, &kernel_vsyscall_event, NULL);

    vmi_resume_vm(vmi);

    printf("Finished with test.\n");

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return 0;
}

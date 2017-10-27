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
vmi_event_t cr3_event;
vmi_event_t msr_syscall_lm_event;
vmi_event_t msr_syscall_compat_event;
vmi_event_t msr_syscall_sysenter_event;

vmi_event_t kernel_vdso_event;
vmi_event_t kernel_vsyscall_event;
vmi_event_t kernel_sysenter_target_event;

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
 * MSR_LSTAR    -    long mode SYSCALL target
 * MSR_CSTAR    -    compat mode SYSCALL target
 *
 * Note that modern code tends to employ the sysenter and/or vDSO mechanisms for
 *    performance reasons.
 */

event_response_t msr_syscall_sysenter_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    print_event(*event);

    vmi_clear_event(vmi, &msr_syscall_sysenter_event, NULL);
    return 0;
}

event_response_t syscall_compat_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    print_event(*event);

    vmi_clear_event(vmi, &msr_syscall_compat_event, NULL);
    return 0;
}

event_response_t vsyscall_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    print_event(*event);

    vmi_clear_event(vmi, &kernel_vsyscall_event, NULL);
    return 0;
}

event_response_t ia32_sysenter_target_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    print_event(*event);

    vmi_clear_event(vmi, &kernel_sysenter_target_event, NULL);
    return 0;
}

event_response_t syscall_lm_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    print_event(*event);

    vmi_clear_event(vmi, &msr_syscall_lm_event, NULL);
    return 0;
}

event_response_t cr3_one_task_callback(vmi_instance_t vmi, vmi_event_t *event)
{

    vmi_pid_t pid = -1;
    vmi_dtb_to_pid(vmi, event->reg_event.value, &pid);

    printf("one_task callback\n");
    if (event->reg_event.value == cr3) {
        printf("My process with PID %"PRIi32", CR3=%"PRIx64" is executing on vcpu %"PRIu32". Previous CR3=%"PRIx64"\n",
               pid, event->reg_event.value, event->vcpu_id, event->reg_event.previous);
        msr_syscall_sysenter_event.mem_event.in_access = VMI_MEMACCESS_X;
        msr_syscall_sysenter_event.callback=msr_syscall_sysenter_cb;
        kernel_sysenter_target_event.mem_event.in_access = VMI_MEMACCESS_X;
        kernel_sysenter_target_event.callback=ia32_sysenter_target_cb;
        kernel_vsyscall_event.mem_event.in_access = VMI_MEMACCESS_X;
        kernel_vsyscall_event.callback=vsyscall_cb;

        if (vmi_register_event(vmi, &msr_syscall_sysenter_event) == VMI_FAILURE)
            fprintf(stderr, "Could not install sysenter syscall handler.\n");
        if (vmi_register_event(vmi, &kernel_sysenter_target_event) == VMI_FAILURE)
            fprintf(stderr, "Could not install sysenter syscall handler.\n");
        if (vmi_register_event(vmi, &kernel_vsyscall_event) == VMI_FAILURE)
            fprintf(stderr, "Could not install sysenter syscall handler.\n");
    } else {
        printf("PID %i is executing, not my process!\n", pid);
        vmi_clear_event(vmi, &msr_syscall_sysenter_event, NULL);
    }
    return 0;
}

event_response_t cr3_all_tasks_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi_pid_t pid = -1;
    vmi_dtb_to_pid(vmi, event->reg_event.value, &pid);
    printf("PID %i with CR3=%"PRIx64" executing on vcpu %"PRIu32". Previous CR3=%"PRIx64"\n",
           pid, event->reg_event.value, event->vcpu_id, event->reg_event.previous);

    msr_syscall_sysenter_event.mem_event.in_access = VMI_MEMACCESS_X;
    msr_syscall_sysenter_event.callback=msr_syscall_sysenter_cb;

    if (vmi_register_event(vmi, &msr_syscall_sysenter_event) == VMI_FAILURE)
        fprintf(stderr, "Could not install sysenter syscall handler.\n");
    vmi_clear_event(vmi, &msr_syscall_sysenter_event, NULL);
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

    reg_t lstar = 0;
    addr_t phys_lstar = 0;
    reg_t cstar = 0;
    addr_t phys_cstar = 0;
    reg_t sysenter_ip = 0;
    addr_t phys_sysenter_ip = 0;

    addr_t ia32_sysenter_target = 0;
    addr_t phys_ia32_sysenter_target = 0;
    addr_t vsyscall = 0;
    addr_t phys_vsyscall = 0;

    char *name = NULL;
    vmi_pid_t pid = -1;

    if (argc < 2) {
        fprintf(stderr, "Usage: events_example <name of VM> <PID of process to track {optional}>\n");
        exit(1);
    }

    // Arg 1 is the VM name.
    name = argv[1];

    // Arg 2 is the pid of the process to track.
    if (argc == 3)
        pid = (int) strtoul(argv[2], NULL, 0);

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* initialize the libvmi library */
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS,
                              NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    printf("LibVMI init succeeded!\n");

    // Get the cr3 for this process.
    if (pid != -1) {
        vmi_pid_to_dtb(vmi, pid, &cr3);
        printf("CR3 for process (%d) == %llx\n", pid, (unsigned long long)cr3);
    }

    // Get the value of lstar and cstar for the system.
    // NOTE: all vCPUs have the same value for these registers
    vmi_get_vcpureg(vmi, &lstar, MSR_LSTAR, 0);
    vmi_get_vcpureg(vmi, &cstar, MSR_CSTAR, 0);
    vmi_get_vcpureg(vmi, &sysenter_ip, SYSENTER_EIP, 0);
    printf("vcpu 0 MSR_LSTAR == %llx\n", (unsigned long long)lstar);
    printf("vcpu 0 MSR_CSTAR == %llx\n", (unsigned long long)cstar);
    printf("vcpu 0 MSR_SYSENTER_IP == %llx\n", (unsigned long long)sysenter_ip);

    vmi_translate_ksym2v(vmi, "ia32_sysenter_target", &ia32_sysenter_target);
    printf("ksym ia32_sysenter_target == %llx\n", (unsigned long long)ia32_sysenter_target);

    /* Per Linux ABI, this VA represents the start of the vsyscall page
     *  If vsyscall support is enabled (deprecated or disabled on many newer
     *  3.0+ kernels), it is accessible at this address in every process.
     */
    vsyscall = 0xffffffffff600000;

    // Translate to a physical address.
    vmi_translate_kv2p(vmi, lstar, &phys_lstar);
    printf("Physical LSTAR == %llx\n", (unsigned long long)phys_lstar);

    vmi_translate_kv2p(vmi, cstar, &phys_cstar);
    printf("Physical CSTAR == %llx\n", (unsigned long long)phys_cstar);

    vmi_translate_kv2p(vmi, sysenter_ip, &phys_sysenter_ip);
    printf("Physical SYSENTER_IP == %llx\n", (unsigned long long)phys_sysenter_ip);

    vmi_translate_kv2p(vmi,ia32_sysenter_target, &phys_ia32_sysenter_target);
    printf("Physical ia32_sysenter_target == %llx\n", (unsigned long long)ia32_sysenter_target);
    vmi_translate_kv2p(vmi,vsyscall,&phys_vsyscall);
    printf("Physical phys_vsyscall == %llx\n", (unsigned long long)phys_vsyscall);


    // Get only the page that the handler starts.
    printf("LSTAR Physical PFN == %llx\n", (unsigned long long)(phys_lstar >> 12));
    printf("CSTAR Physical PFN == %llx\n", (unsigned long long)(phys_cstar >> 12));
    printf("SYSENTER_IP Physical PFN == %llx\n", (unsigned long long)(phys_sysenter_ip >> 12));
    printf("phys_vsyscall Physical PFN == %llx\n", (unsigned long long)(phys_vsyscall >> 12));
    printf("phys_ia32_sysenter_target Physical PFN == %llx\n", (unsigned long long)(phys_ia32_sysenter_target >> 12));

    /* Configure an event to track when the process is running.
     * (The CR3 register is updated on task context switch, allowing
     *  us to follow as various tasks are scheduled and run upon the CPU)
     */
    memset(&cr3_event, 0, sizeof(vmi_event_t));
    cr3_event.version = VMI_EVENTS_VERSION;
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.reg_event.reg = CR3;

    /* Observe only write events to the given register.
     *   NOTE: read events are unsupported at this time.
     */
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;

    /* Optional (default = 0): Trigger on change
     *  Causes events to be delivered by the hypervisor to this monitoring
     *   program if and only if the register value differs from that previously
     *   observed.
     *  Usage: cr3_event.reg_event.onchange = 1;
     *
     * Optional (default = 0): Asynchronous event delivery
     *  Causes events to be delivered by the hypervisor to this monitoring
     *   program if and only if the register value differs from that previously
     *   observed.
     *  Usage: cr3_event.reg_event.async =1;
     */

    if (pid == -1) {
        cr3_event.callback = cr3_all_tasks_callback;
        vmi_register_event(vmi, &cr3_event);
    } else {
        cr3_event.callback = cr3_one_task_callback;
        /* This acts as a filter: if the CR3 value at time of event == the CR3
         *  we wish to inspect, then the callback will be invoked. Otherwise,
         *  no action is taken.
         */
        cr3_event.reg_event.equal = cr3;
        vmi_register_event(vmi, &cr3_event);
    }

    // Setup a default event for tracking memory at the syscall handler.
    // But don't install it; that will be done by the cr3 handler.
    memset(&msr_syscall_sysenter_event, 0, sizeof(vmi_event_t));
    msr_syscall_sysenter_event.version = VMI_EVENTS_VERSION;
    msr_syscall_sysenter_event.type = VMI_EVENT_MEMORY;
    msr_syscall_sysenter_event.mem_event.gfn = phys_sysenter_ip >> 12;

    memset(&kernel_sysenter_target_event, 0, sizeof(vmi_event_t));
    kernel_sysenter_target_event.version = VMI_EVENTS_VERSION;
    kernel_sysenter_target_event.type = VMI_EVENT_MEMORY;
    kernel_sysenter_target_event.mem_event.gfn = phys_ia32_sysenter_target >> 12;

    memset(&kernel_vsyscall_event, 0, sizeof(vmi_event_t));
    kernel_vsyscall_event.version = VMI_EVENTS_VERSION;
    kernel_vsyscall_event.type = VMI_EVENT_MEMORY;
    kernel_vsyscall_event.mem_event.gfn = phys_vsyscall >> 12;

    while (!interrupted) {
        printf("Waiting for events...\n");
        status = vmi_events_listen(vmi,500);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }
    printf("Finished with test.\n");

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    return 0;
}

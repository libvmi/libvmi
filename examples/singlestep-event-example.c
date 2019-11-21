/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Matthew Fusaro (matthew.fusaro@zentific.com)
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
#include <unistd.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

static vmi_event_t single_event = {0};
static vmi_instance_t vmi = {0};

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

void exit_cleanup()
{
    vmi_destroy(vmi);
}

event_response_t single_step_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi = vmi;
    printf("Single-step event: VCPU:%u  GFN %"PRIx64" GLA %016"PRIx64"\n",
           event->vcpu_id,
           event->ss_event.gfn,
           event->ss_event.gla);

    return 0;
}

int main (int argc, char **argv)
{
    struct sigaction act;

    char *name = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name of VM> \n", argv[0]);
        exit(1);
    }

    // Arg 1 is the VM name.
    name = argv[1];

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, VMI_XEN, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    printf("LibVMI init succeeded!\n");
    // register cleanup routine
    atexit(&exit_cleanup);

    // get number of vcpus
    unsigned int num_vcpus = vmi_get_num_vcpus(vmi);

    // Single step setup
    memset(&single_event, 0, sizeof(vmi_event_t));
    single_event.version = VMI_EVENTS_VERSION;
    single_event.type = VMI_EVENT_SINGLESTEP;
    single_event.callback = single_step_callback;
    single_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(single_event.ss_event, 0);

    // register
    if (VMI_FAILURE == vmi_register_event(vmi, &single_event)) {
        fprintf(stderr, "Failed to register singlestep event\n");
        return 1;
    }

    // event loop
    while (!interrupted) {
        printf("Waiting for events...\n");
        if (VMI_FAILURE == vmi_events_listen(vmi,500)) {
            fprintf(stderr, "Failed to listen on events\n");
            return 1;
        }
    }

    // toggling singlestep off/on

    // pause before cleaning the ring
    // this prevents new events from being queued
    if (VMI_FAILURE == vmi_pause_vm(vmi)) {
        fprintf(stderr, "Failed to pause VM\n");
        return 1;
    }
    // clean event ring
    if (VMI_FAILURE == vmi_events_listen(vmi, 0)) {
        fprintf(stderr, "Failed to pause VM\n");
        return 1;
    }

    // disable singlestep on all vcpus
    for (unsigned int vcpu=0; vcpu < num_vcpus; vcpu++) {
        if (VMI_FAILURE == vmi_toggle_single_step_vcpu(vmi, &single_event, vcpu, false)) {
            fprintf(stderr, "Failed to stop singlestepping on VCPU %d\n", vcpu);
            return 1;
        }
    }
    printf("Singlestep stopped\n");
    if (VMI_FAILURE == vmi_resume_vm(vmi)) {
        fprintf(stderr, "Failed to resume VM\n");
        return 1;
    }

    // VM should be running
    // sleep(5);

    // toggle singlestep back ON
    // pause before changing VM state
    if (VMI_FAILURE == vmi_pause_vm(vmi)) {
        fprintf(stderr, "Failed to pause VM\n");
        return 1;
    }
    printf("Restarting singlestep\n");
    for (unsigned int vcpu=0; vcpu < num_vcpus; vcpu++) {
        if (VMI_FAILURE == vmi_toggle_single_step_vcpu(vmi, &single_event, vcpu, true)) {
            fprintf(stderr, "Failed to enable singlestep on VCPU %d\n", vcpu);
            return 1;
        }
    }
    if (VMI_FAILURE == vmi_resume_vm(vmi)) {
        fprintf(stderr, "Failed to resume VM\n");
        return 1;
    }
    // process a few more singlestep events
    for (int i=0; i < 5; i++) {
        printf("Waiting for events...\n");
        if (VMI_FAILURE == vmi_events_listen(vmi,500)) {
            fprintf(stderr, "Failed to listen on events\n");
            return 1;
        }
    }
    printf("Finished with test.\n");

    // singlestep event will be cleared by vmi_destroy(), called
    // by exit_cleanup() routine configured earlier upon exit

    return 0;
}

/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

event_response_t cr3_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi;
    printf("CR3 write happened: Value=0x%"PRIx64"\n", event->reg_event.value);
    return VMI_EVENT_RESPONSE_NONE;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi;
    status_t status;
    vmi_init_data_t init_data = {0};
    vmi_mode_t mode;

    /* this is the VM or file that we are looking at */
    if (argc < 2) {
        printf("Usage: %s <vmname> [<socket>]\n", argv[0]);
        return 1;
    }

    char *name = argv[1];

    if (argc == 3) {
        char *path = argv[2];

        // fill init_data
        init_data.count = 1;
        init_data.entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data.entry[0].data = strdup(path);
    }

    if (VMI_FAILURE == vmi_get_access_mode(NULL, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, &init_data, &mode)) {
        fprintf(stderr, "Failed to get access mode\n");
        return 1;
    }

    if (VMI_FAILURE ==
        vmi_init(&vmi, mode, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, &init_data, NULL)) {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        return 1;
    }

    struct sigaction act;
    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* pause the vm for consistent memory access */
    if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to pause VM\n");
        goto error_exit;
    }

    vmi_event_t cr3_event = {0};
    cr3_event.version = VMI_EVENTS_VERSION;
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.callback = cr3_callback;
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;

    // register event
    if (vmi_register_event(vmi, &cr3_event) == VMI_FAILURE)
        goto error_exit;

    if (vmi_resume_vm(vmi) ==  VMI_FAILURE)
        goto error_exit;

    printf("Waiting for events...\n");
    while (!interrupted) {
        status = vmi_events_listen(vmi, 500);
        if (status == VMI_FAILURE)
            printf("Failed to listen on events\n");
    }

error_exit:
    vmi_clear_event(vmi, &cr3_event, NULL);

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    return 0;
}

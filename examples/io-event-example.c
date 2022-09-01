/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Anton Belousov <blsvntntx@gmail.com>
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
#include <getopt.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

event_response_t io_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi;
    if (event->io_event.port == 0x0CF8)
        printf("IO cb: Port: 0x%"PRIx32", Address: %"PRIx64"\n", event->io_event.port, event->x86_regs->rax);

    return VMI_EVENT_RESPONSE_NONE;
}

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    vmi_event_t io_event = {0};
    struct sigaction act = {0};
    vmi_init_data_t *init_data = NULL;
    vmi_mode_t mode = {0};
    uint64_t domid = 0;
    uint8_t init = VMI_INIT_DOMAINNAME;
    void *input = NULL;
    int retcode = 1;

    if ( argc <= 2 ) {
        printf("Usage: %s\n", argv[0]);
        printf("\t -n/--name <domain name>\n");
        printf("\t -d/--domid <domain id>\n\n");
        return false;
    }

    const struct option long_opts[] = {
        {"name", required_argument, NULL, 'n'},
        {"domid", required_argument, NULL, 'd'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "n:d:";
    int c;
    int long_index = 0;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
        switch (c) {
            case 'n':
                input = optarg;
                break;
            case 'd':
                init = VMI_INIT_DOMAINID;
                domid = strtoull(optarg, NULL, 0);
                input = (void*)&domid;
                break;
            default:
                printf("Unknown option\n");
                return false;
        }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_get_access_mode(NULL, input, init, init_data, &mode)) {
        fprintf(stderr, "Failed to get access mode\n");
        goto error_exit;
    }

    if (VMI_FAILURE == vmi_init(&vmi, mode, input, init | VMI_INIT_EVENTS, init_data, NULL)) {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        goto error_exit;
    }
    printf("LibVMI init\n");

    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    SETUP_IO_EVENT(&io_event, io_cb);

    if (VMI_FAILURE == vmi_register_event(vmi, &io_event)) {
        fprintf(stderr, "Failed to register IO event\n");
        goto error_exit;
    }
    printf("Registered event\n");
    printf("Listening on events...\n");

    while (!interrupted) {
        if (VMI_FAILURE == vmi_events_listen(vmi,500)) {
            fprintf(stderr, "Failed to listen on VMI events\n");
            goto error_exit;
        }
    }

    retcode = 0;
error_exit:
    vmi_clear_event(vmi, &io_event, NULL);

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}

/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
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
#include <glib.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#define LIBVMI_EXTRA_GLIB
#include <libvmi/libvmi_extra.h>

reg_t cr3;
vmi_event_t cr3_event;
GSList *va_pages;

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

void free_va_pages()
{
    GSList *free_this = va_pages;
    while (va_pages) {
        g_free(va_pages->data);
        va_pages=va_pages->next;
    }
    g_slist_free(free_this);
    va_pages = NULL;
}

event_response_t cr3_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    va_pages = vmi_get_va_pages(vmi, event->reg_event.value);

    printf("CR3: 0x%lx. Pages: %u\n", event->reg_event.value, g_slist_length(va_pages));

    GSList *loop = va_pages;
    while (loop) {
        page_info_t *page = loop->data;

        // Demonstrate using access_context_t
        ACCESS_CONTEXT(ctx,
                       .translate_mechanism = VMI_TM_PROCESS_DTB,
                       .addr = page->vaddr,
                       .pt = event->reg_event.value);

        uint64_t test;
        if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &test)) {
            printf("Page in virtual address space of DTB 0x%"PRIx64" unaccessible: 0x%"PRIx64".\t"
                   "Size: 0x%"PRIx64"\n",
                   ctx.dtb, page->vaddr, (uint64_t)page->size);
        }

        loop=loop->next;
    }
    free_va_pages();
    return 0;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    status_t status = VMI_SUCCESS;
    struct sigaction act;
    int retcode = 1;
    vmi_init_data_t *init_data = NULL;

    char *name = NULL;
    va_pages = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name of VM> [<socket>]\n", argv[0]);
        return retcode;
    }

    // Arg 1 is the VM name.
    name = argv[1];

    // KVMi socket ?
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

    // Initialize the libvmi library.
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS,
                              init_data, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }

    printf("LibVMI init succeeded!\n");

    /* Configure an event to track when the process is running.
     * (The CR3 register is updated on task context switch, allowing
     *  us to follow as various tasks are scheduled and run upon the CPU)
     */
    SETUP_REG_EVENT(&cr3_event, CR3, VMI_REGACCESS_W, 0, cr3_callback);
    vmi_register_event(vmi, &cr3_event);

    while (!interrupted) {
        printf("Waiting for events...\n");
        status = vmi_events_listen(vmi,500);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }
    printf("Finished with test.\n");

    free_va_pages();
    retcode = 0;
error_exit:
    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}

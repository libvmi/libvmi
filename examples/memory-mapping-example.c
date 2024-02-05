#include <libvmi/libvmi.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

int main(int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;
    mapped_regions_t mapping = {0};

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <vmname> [<socket>]\n", argv[0]);
        return retcode;
    }

    char *name = argv[1];

    if (argc == 3) {
        char *path = argv[2];

        // fill init_data
        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    vmi_init_error_t init_error;

    // initialize the libvmi library
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME, init_data,
                              VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, &init_error)) {
        printf("Failed to init LibVMI library. error: %d\n", init_error);
        goto cleanup;
    }

    access_context_t accessContext = {0};
    accessContext.version = ACCESS_CONTEXT_VERSION;
    accessContext.translate_mechanism = VMI_TM_PROCESS_PID;
    accessContext.pid = 0;
    accessContext.addr = 0;

    // map the whole kernel address space
    if (vmi_mmap_guest_2(vmi, &accessContext, -1, PROT_READ, &mapping) == VMI_FAILURE) {
        printf("Unable to map guest memory\n");
        goto cleanup;
    }

    if (mapping.size == 0) {
        printf("No pages found in given range\n");
        goto cleanup;
    }

    printf("Contiguous regions:\n");
    for (size_t i = 0; i < mapping.size; ++i) {
        printf("%zu: 0x%"PRIx64", num_pages: %zu\n", i, mapping.regions[i].start_va, mapping.regions[i].num_pages);
    }

    retcode = 0;

cleanup:
    vmi_free_mapped_regions(vmi, &mapping);

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}

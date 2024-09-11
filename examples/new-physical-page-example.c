#include <libvmi/libvmi.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;
    addr_t new_gfn = 0;

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

    /* initialize the libvmi library */
    vmi_init_error_t init_error;
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME, init_data,
                              VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, &init_error)) {
        printf("Failed to init LibVMI library. error: %d\n", init_error);
        goto error_exit;
    }

    new_gfn = vmi_get_next_available_gfn(vmi);
    printf("Next available gfn: 0x%"PRIx64"\n", new_gfn);

    if (vmi_alloc_gfn(vmi, new_gfn) != VMI_SUCCESS) {
        printf("Unable to alloc new gfn\n");
        new_gfn = 0;
        goto error_exit;
    }
    addr_t target_addr = new_gfn << 12;

    uint64_t content = 0xCAFECAFECAFECAFE;
    if (vmi_write_64_pa(vmi, target_addr, &content) != VMI_SUCCESS) {
        printf("Unable to write to newly allocated physical page\n");
        goto error_exit;
    }

    uint64_t retrieved_data = 0;
    if (vmi_read_64_pa(vmi, target_addr, &retrieved_data) != VMI_SUCCESS) {
        printf("Unable to read from newly allocated physical page\n");
        goto error_exit;
    }
    printf("Retrieved value: 0x%"PRIx64"\n", retrieved_data);

    retcode = 0;

error_exit:
    if (new_gfn && vmi_free_gfn(vmi, new_gfn) != VMI_SUCCESS) {
        printf("Unable to free new gfn\n");
        retcode = 1;
    }

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}

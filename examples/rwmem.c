/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>

#define LIBVMI_EXTRA_GLIB
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/x86.h>

static vmi_instance_t vmi;
static os_t os;
static page_mode_t pm;
static addr_t target_pagetable;

static bool setup_vmi(vmi_instance_t *vmi, char* domain, uint64_t domid, char* json, char *kvmi, bool init_events, bool init_paging)
{
    printf("Init vmi, init_events: %i init_paging %i domain %s domid %lu json %s kvmi %s\n",
           init_events, init_paging, domain ?: "-", domid, json ?: "-", kvmi ?: "-");

    uint64_t options = (init_events ? VMI_INIT_EVENTS : 0) |
                       (domain ? VMI_INIT_DOMAINNAME : VMI_INIT_DOMAINID);
    vmi_mode_t mode = kvmi ? VMI_KVM : VMI_XEN;
    const void *d = domain ?: (void*)&domid;

    vmi_init_data_t *data = NULL;
    if ( kvmi ) {
        data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        data->count = 1;
        data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        data->entry[0].data = kvmi;
    }

    status_t status = vmi_init(vmi, mode, d, options, data, NULL);

    free(data);

    if ( VMI_FAILURE == status )
        return false;

    if ( json ) {
        if ( VMI_OS_UNKNOWN == (os = vmi_init_os(*vmi, VMI_CONFIG_JSON_PATH, json, NULL)) ) {
            fprintf(stderr, "Error in vmi_init_os!\n");
            vmi_destroy(*vmi);
            return false;
        }

        pm = vmi_get_page_mode(*vmi, 0);
    } else if ( init_paging && VMI_PM_UNKNOWN == (pm = vmi_init_paging(*vmi, 0)) ) {
        fprintf(stderr, "Error in vmi_init_paging!\n");
        vmi_destroy(*vmi);
        return false;
    }

    registers_t regs = {0};
    if ( VMI_FAILURE == vmi_get_vcpuregs(*vmi, &regs, 0) ) {
        fprintf(stderr, "Error in vmi_get_vcpuregs!\n");
        vmi_destroy(*vmi);
        return false;
    }

    target_pagetable = regs.x86.cr3;

    return true;
}

static void do_list_pages(addr_t pagetable)
{
    printf("Mappings in pagetable at 0x%lx:\n", pagetable);
    GSList *va_pages = vmi_get_va_pages(vmi, pagetable);
    GSList *loop = va_pages;
    while (loop) {
        page_info_t *info = loop->data;
        uint64_t entry = info->size == VMI_PS_4KB ? info->x86_ia32e.pte_value :
                         info->size == VMI_PS_2MB ? info->x86_ia32e.pgd_value :
                         info->x86_ia32e.pdpte_value;

        loop = loop->next;

        printf("\t0x%lx [0x%x %s%c] -> 0x%lx\n",
               info->vaddr, info->size,
               READ_WRITE(entry) ? "rw" : "r-",
               NX(entry) ? '-' : 'x',
               info->paddr
              );

        free(info);
    }

    g_slist_free(va_pages);
}

static void usage(void)
{
    printf("Usage:\n");
    printf("\t --domid <domid>\n");
    printf("\t --read <address>\n");
    printf("\t --write <address>\n");
    printf("\t --file <input/output file>\n");
    printf("\t --limit <input/output limit>\n");

    printf("Optional:\n");
    printf("\t --pagetable <address> (-1 for physical memory access)\n");
    printf("\t --kvmi <socket>\n");
    printf("\t --list-pages\n");
}

int main(int argc, char** argv)
{
    addr_t pagetable = 0;
    int c, long_index = 0;
    const struct option long_opts[] = {
        {"help", no_argument, NULL, 'h'},
        {"domid", required_argument, NULL, 'd'},
        {"read", required_argument, NULL, 'r'},
        {"write", required_argument, NULL, 'w'},
        {"limit", required_argument, NULL, 'L'},
        {"file", required_argument, NULL, 'f'},
        {"pagetable", required_argument, NULL, 'p'},
        {"kvmi", required_argument, NULL, 'K'},
        {"list-pages", no_argument, NULL, 'l'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:j:r:w:L:f:p:k:l";
    bool read = false, write = false, list_pages = false;
    size_t limit = 0;
    addr_t address = 0;
    char *filepath = NULL;
    char *kvmi = NULL;
    uint32_t domid = 0;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1) {
        switch (c) {
            case 'd':
                domid = strtoul(optarg, NULL, 0);
                break;
            case 'r':
                read = true;
                address = strtoull(optarg, NULL, 0);
                break;
            case 'w':
                write = true;
                address = strtoull(optarg, NULL, 0);
                break;
            case 'L':
                limit = strtoull(optarg, NULL, 0);
                break;
            case 'f':
                filepath = optarg;
                break;
            case 'p':
                pagetable = strtoull(optarg, NULL, 0);
                break;
            case 'K':
                kvmi = optarg;
                break;
            case 'l':
                list_pages = true;
                break;
            case 'h': /* fall-through */
            default:
                usage();
                return -1;
        };
    }

    if ( !domid || (!read && !write && !list_pages) || (read && write) || (!list_pages && (!limit || !filepath)) ) {
        usage();
        return -1;
    }

    if ( !setup_vmi(&vmi, NULL, domid, NULL, kvmi, false, true) )
        return -1;

    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_DTB,
                   .pt = target_pagetable,
                   .addr = address
                  );

    if ( pagetable ) {
        if ( pagetable == ~0ull ) {
            ctx.translate_mechanism = VMI_TM_NONE;
            ctx.dtb = 0;
        } else
            ctx.dtb = pagetable;
    }

    if (list_pages ) {
        do_list_pages(ctx.pt);
        goto done;
    }

    size_t fsize = 0;
    FILE *i = fopen(filepath, read ? "w+" : "r");

    if (!i) {
        printf("Failed to open %s\n", filepath);
        goto done;
    }

    // Do large reads/writes in chunks
    unsigned int iters = limit < VMI_PS_4KB ? 1 : limit / VMI_PS_4KB;
    while ( iters-- ) {
        unsigned long access_length;
        unsigned char buffer[VMI_PS_4KB] = {0};

        if ( !limit )
            break;
        if ( limit < VMI_PS_4KB ) {
            access_length = limit;
            limit = 0;
        } else {
            access_length = VMI_PS_4KB;
            limit -= VMI_PS_4KB;
        }

        if ( read ) {
            if ( VMI_SUCCESS == vmi_read(vmi, &ctx, access_length, (void*)&buffer, NULL) )
                printf("Read operation success: %lu bytes from 0x%lx\n", access_length, ctx.addr);
            else
                printf("Read operation failed from 0x%lx\n", ctx.addr);

            if ( 1 != fwrite(&buffer, access_length, 1, i) ) {
                printf("Failed to save data in %s\n", filepath);
                break;
            }
        }

        if ( write ) {
            if ( !(fsize = fread(&buffer, 1, access_length, i)) ) {
                printf("Failed to read from %s\n", filepath);
                break;
            }

            if ( VMI_SUCCESS == vmi_write(vmi, &ctx, fsize, (void*)&buffer, NULL) )
                printf("Write operation success: %lu bytes to 0x%lx\n", fsize, ctx.addr);
            else
                printf("Write operation failed to 0x%lx\n", ctx.addr);

            if ( fsize < access_length ) {
                printf("Nothing left in %s to read\n", filepath);
                break;
            }
        }

        ctx.addr += access_length;
    }

    fclose(i);

done:
    vmi_destroy(vmi);
    return 0;
}

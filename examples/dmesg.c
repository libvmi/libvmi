/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel (tamas@tklengyel.com)
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

/*
 * Dump Linux dmesg log, loosely based on:
 *  https://github.com/torvalds/linux/blob/master/scripts/gdb/linux/dmesg.py
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>

#include <libvmi/libvmi.h>
#define LIBVMI_EXTRA_JSON
#include <libvmi/libvmi_extra.h>

static vmi_instance_t vmi;

static bool init_vmi(int argc, char **argv)
{
    uint64_t domid = 0;
    uint8_t init = VMI_INIT_DOMAINNAME, config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *input = NULL, *config = NULL;

    if ( argc <= 2 ) {
        printf("Usage: %s\n", argv[0]);
        printf("\t -n/--name <domain name>\n");
        printf("\t -d/--domid <domain id>\n");
        printf("\t -j/--json <path to kernel's json profile>\n");
        return false;
    }

    const struct option long_opts[] = {
        {"name", required_argument, NULL, 'n'},
        {"domid", required_argument, NULL, 'd'},
        {"json", required_argument, NULL, 'j'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "n:d:j:s:";
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
            case 'j':
                config_type = VMI_CONFIG_JSON_PATH;
                config = (void*)optarg;
                break;
            default:
                printf("Unknown option\n");
                return false;
        }

    if (VMI_FAILURE == vmi_init_complete(&vmi, input, init, NULL, config_type, config, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return false;
    }

    return true;
}

int main (int argc, char **argv)
{
    int retcode = 1;
    json_object *json = NULL;
    unsigned char* log_buf = NULL;

    if ( !init_vmi(argc, argv) )
        return retcode;

    if (VMI_OS_LINUX != vmi_get_ostype(vmi)) {
        printf("Target VM is not Linux\n");
        goto error_exit;
    }

    if ( !(json = vmi_get_kernel_json(vmi)) ) {
        printf("Target has no JSON profile specified\n");
        goto error_exit;
    }

    if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to pause VM\n");
        goto error_exit;
    }

    addr_t log_buf_addr;
    if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, "__log_buf", &log_buf_addr) )
        goto error_exit;

    uint32_t log_first_idx;
    if ( VMI_FAILURE == vmi_read_32_ksym(vmi, "log_first_idx", &log_first_idx) )
        goto error_exit;

    uint32_t log_next_idx;
    if ( VMI_FAILURE == vmi_read_32_ksym(vmi, "log_next_idx", &log_next_idx) )
        goto error_exit;

    uint32_t log_buf_len;
    if ( VMI_FAILURE == vmi_read_32_ksym(vmi, "log_buf_len", &log_buf_len) )
        goto error_exit;

    addr_t length_offset;
    if ( VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, json, "printk_log", "len", &length_offset) )
        goto error_exit;

    addr_t text_len_offset;
    if ( VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, json, "printk_log", "text_len", &text_len_offset) )
        goto error_exit;

    addr_t time_stamp_offset;
    if ( VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, json, "printk_log", "ts_nsec", &time_stamp_offset) )
        goto error_exit;

    addr_t text_offset;
    if ( VMI_FAILURE == vmi_get_struct_size_from_json(vmi, json, "printk_log", &text_offset) )
        goto error_exit;

    /*
    printf("Log buf: 0x%lx\n", log_buf_addr);
    printf("Log first idx: 0x%lx\n", log_first_idx);
    printf("Log next idx: 0x%lx\n", log_next_idx);
    printf("Log buf length: 0x%lx\n", log_buf_len);
    printf("printk_log size: %lu\n", text_offset);
    printf("printk_log.ts_nsec: %lu\n", time_stamp_offset);
    printf("printk_log.len: %lu\n", length_offset);
    printf("printk_log.text_len: %lu\n", text_len_offset);
    */

    /* Ring buffer unrolling */
    size_t length = 0, log_buf_2nd_half = 0;
    if (log_first_idx < log_next_idx) {
        length = log_next_idx - log_first_idx;
        log_buf = malloc(length);

        if ( !log_buf )
            goto error_exit;

        if ( VMI_FAILURE == vmi_read_va(vmi, log_buf_addr + log_first_idx, 0, length, log_buf, NULL) )
            goto error_exit;
    } else {
        log_buf_2nd_half = log_buf_len - log_first_idx;
        length += log_buf_2nd_half;
        length += log_next_idx;
        log_buf = malloc(length);

        if ( !log_buf )
            goto error_exit;

        if ( VMI_FAILURE == vmi_read_va(vmi, log_buf_addr + log_first_idx, 0, log_buf_2nd_half, log_buf, NULL) )
            goto error_exit;

        if ( VMI_FAILURE == vmi_read_va(vmi, log_buf_addr, 0, log_next_idx, log_buf + log_buf_2nd_half, NULL) )
            goto error_exit;
    }

    addr_t pos = 0;
    while ( pos < length ) {

        uint16_t len = *(uint16_t*)&log_buf[pos + length_offset];

        if ( !len && log_buf_2nd_half && pos < log_buf_2nd_half ) {
            // ring loop-around
            pos = log_buf_2nd_half;
            continue;
        }

        uint16_t text_len = *(uint16_t*)&log_buf[pos + text_len_offset];
        unsigned char *text = &log_buf[pos + text_offset];

        unsigned char *toprint = malloc(text_len + 1);
        if ( !toprint )
            goto error_exit;

        /* text is not null terminated so we copy it and add \0 */
        memcpy(toprint, text, text_len);
        toprint[text_len] = '\0';
        printf("%s\n", toprint);
        free(toprint);

        pos += len;
    }

    retcode = 0;

error_exit:
    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    if ( log_buf )
        free(log_buf);

    return retcode;
}

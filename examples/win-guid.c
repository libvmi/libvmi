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

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <glib.h>

#include "win-guid.h"

#define PAGE_SIZE           0x1000
#define MAX_HEADER_SIZE     1024
#define PDB_FILENAME_LENGTH 12

static addr_t max_mem;

status_t check_sections(vmi_instance_t vmi, addr_t image_base_p, uint8_t *pe) {

    struct pe_header *pe_header = NULL;
    struct dos_header *dos_header = NULL;
    uint16_t optional_header_type = 0;
    peparse_assign_headers(pe, &dos_header, &pe_header, &optional_header_type, NULL, NULL, NULL);

    uint32_t c;
    for(c=0; c < pe_header->number_of_sections; c++) {

        struct section_header section;
        addr_t section_addr = image_base_p
            + dos_header->offset_to_pe
            + sizeof(struct pe_header)
            + pe_header->size_of_optional_header
            + c*sizeof(struct section_header);

        // Read the section from memory
        if ( sizeof(struct section_header) != vmi_read_pa(vmi, section_addr, (uint8_t *)&section, sizeof(struct section_header)) )
            return VMI_FAILURE;

        //printf("S: %s\n", section.short_name);

        // The character array is not null terminated, so only print the first 8 characters!
        if ( !strncmp(section.short_name, "INITKDBG", 8) )
            return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

status_t is_WINDOWS_KERNEL(vmi_instance_t vmi, addr_t base_p, uint8_t *pe) {

    status_t ret = VMI_FAILURE;

    void *optional_pe_header = NULL;
    uint16_t optional_header_type = 0;
    struct export_table et;

    peparse_assign_headers(pe, NULL, NULL, &optional_header_type, &optional_pe_header, NULL, NULL);
    addr_t export_header_offset = peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_EXPORT, &optional_header_type, optional_pe_header, NULL, NULL);

    // The kernel's export table is continuously allocated on the PA level with the PE header
    // This trick may not work for other PE headers (though may work for some drivers)
    if ( base_p + export_header_offset < base_p + VMI_PS_4KB ) {
        uint32_t nbytes = vmi_read_pa(vmi, base_p + export_header_offset, &et, sizeof(struct export_table));
        if(nbytes == sizeof(struct export_table) && !(et.export_flags || !et.name)) {
            char *name = vmi_read_str_pa(vmi, base_p + et.name);

            if(name) {
                if(strcmp("ntoskrnl.exe", name)==0)
                    ret = VMI_SUCCESS;

                free(name);
            }
        }
    }

    // The export header may be stripped from the kernel so check section names.
    // This is commonly the case with Windows 10.
    if ( ret == VMI_FAILURE ) {
        ret = check_sections(vmi, base_p, pe);
    }

    return ret;
}

void print_os_version(uint8_t* pe) {

    uint16_t major_os_version = 0;
    uint16_t minor_os_version = 0;
    uint16_t optional_header_type = 0;
    struct optional_header_pe32 *oh32 = NULL;
    struct optional_header_pe32plus *oh32plus = NULL;

    peparse_assign_headers(pe, NULL, NULL, &optional_header_type, NULL, &oh32, &oh32plus);

    printf("\tVersion: ");

    if(optional_header_type == IMAGE_PE32_MAGIC) {

        major_os_version=oh32->major_os_version;
        minor_os_version=oh32->minor_os_version;

        printf("32-bit");
    } else
    if(optional_header_type == IMAGE_PE32_PLUS_MAGIC) {

        major_os_version=oh32plus->major_os_version;
        minor_os_version=oh32plus->minor_os_version;

        printf("64-bit");
    }

    if(major_os_version == 3) {
        if (minor_os_version == 1)
                printf(" Windows NT 3.1");
        if (minor_os_version == 5)
                printf(" Windows NT 3.5");
    } else
    if(major_os_version == 4) {
            printf(" Windows NT 4.0");
    } else
    if(major_os_version == 5) {
        if (minor_os_version == 0)
                printf(" Windows 2000");
        if (minor_os_version == 1)
                printf(" Windows XP");
        if (minor_os_version == 2)
                printf(" Windows Server_2003");
    } else
    if(major_os_version == 6) {
        if (minor_os_version == 0)
                printf(" Windows Vista or Server 2008");
        if (minor_os_version == 1)
                printf(" Windows 7");
        if (minor_os_version == 2)
                printf(" Windows 8");
    } else
    if(major_os_version == 10) {
        if (minor_os_version == 0)
                printf(" Windows 10");
    } else {
            printf(" OS version unknown or not Windows\n");
    }

    printf("\n");

}

bool kernel_debug_search(vmi_instance_t vmi, struct cv_info_pdb70 *pdb_header) {
    addr_t i;
    for(i=0; i < max_mem; i += PAGE_SIZE) {
        uint8_t pe[VMI_PS_4KB];
        vmi_read_pa(vmi, i, pe, VMI_PS_4KB);
        uint32_t c;
        for (c=0;c<VMI_PS_4KB-PDB_FILENAME_LENGTH;c++) {
            if(!strncmp((char*)&pe[c], "ntkrnlmp.pdb", PDB_FILENAME_LENGTH) ||
               !strncmp((char*)&pe[c], "ntoskrnl.pdb", PDB_FILENAME_LENGTH) ||
               !strncmp((char*)&pe[c], "ntkrnlpa.pdb", PDB_FILENAME_LENGTH) ||
               !strncmp((char*)&pe[c], "ntkrpamp.pdb", PDB_FILENAME_LENGTH)
            ) {
                vmi_read_pa(vmi, i+c - 2*sizeof(uint32_t) - sizeof(struct guid), pdb_header, sizeof(struct cv_info_pdb70)+PDB_FILENAME_LENGTH);
                if ( pdb_header->cv_signature != RSDS)
                    continue;
                else
                    return 1;
            }
        }
    }
    return 0;
}

void print_guid(vmi_instance_t vmi, addr_t kernel_base_p, uint8_t* pe) {

    uint32_t size_of_image;

    bool debug_directory_valid = 0;
    struct pe_header *pe_header = NULL;
    uint16_t optional_header_type = 0;
    struct optional_header_pe32 *oh32 = NULL;
    struct optional_header_pe32plus *oh32plus = NULL;

    peparse_assign_headers(pe, NULL, &pe_header, &optional_header_type, NULL, &oh32, &oh32plus);
    addr_t debug_offset = peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_DEBUG, NULL, NULL, oh32, oh32plus);

    switch(optional_header_type)
    {
    case IMAGE_PE32_MAGIC:
        size_of_image=oh32->size_of_image;
        break;
    case IMAGE_PE32_PLUS_MAGIC:
        size_of_image=oh32plus->size_of_image;
        break;
    default:
        return;
    }

    struct image_debug_directory debug_directory = { 0 };
    struct cv_info_pdb70 *pdb_header = g_malloc0(sizeof(struct cv_info_pdb70)+PDB_FILENAME_LENGTH+1);
    vmi_read_pa(vmi, kernel_base_p + debug_offset, (uint8_t *)&debug_directory, sizeof(struct image_debug_directory));

    printf("\tPE GUID: %.8x%.5x\n",pe_header->time_date_stamp,size_of_image);

    switch(debug_directory.type)
    {
    case IMAGE_DEBUG_TYPE_CODEVIEW:
        // OK
        debug_directory_valid = 1;
        break;
    case IMAGE_DEBUG_TYPE_MISC:
        printf("This operating system uses .dbg instead of .pdb\n");
        return;
    default:
        //printf("The debug directory header is not in CodeView format, will do a brute-force search!\n");
        break;
    }

    if (debug_directory_valid) {
        if(debug_directory.size_of_data > VMI_PS_4KB/4) {
            // Normal size of the debug directory on Windows 7 for example is 0x25 bytes.
            printf("The size of the debug directory is huge, something might be wrong.\n");
            goto done;
        }

        vmi_read_pa(vmi, kernel_base_p + debug_directory.address_of_raw_data, pdb_header, sizeof(struct cv_info_pdb70)+PDB_FILENAME_LENGTH);

        // The PDB header has to be PDB 7.0
        // http://www.debuginfo.com/articles/debuginfomatch.html
        if(RSDS != pdb_header->cv_signature) {
            printf("The CodeView debug information has to be in PDB 7.0 for the kernel!\n");
            goto done;
        }

    } else {
        if(!kernel_debug_search(vmi, pdb_header))
            goto done;
    }

     printf("\tPDB GUID: ");
     printf("%.8x", pdb_header->signature.data1);
     printf("%.4x", pdb_header->signature.data2);
     printf("%.4x", pdb_header->signature.data3);

     int c;
     for(c=0;c<8;c++) printf("%.2x", pdb_header->signature.data4[c]);

     printf("%.1x", pdb_header->age & 0xf);
     printf("\n");
     printf("\tKernel filename: %s\n", (char*)pdb_header->pdb_file_name);

     if(!strcmp("ntoskrnl.pdb", (char*)pdb_header->pdb_file_name)) {
        printf("\tSingle-processor without PAE\n");
     } else
     if(!strcmp("ntkrnlmp.pdb", (char*)pdb_header->pdb_file_name)) {
        printf("\tMulti-processor without PAE\n");
     } else
     if(!strcmp("ntkrnlpa.pdb", (char*)pdb_header->pdb_file_name)) {
        printf("\tSingle-processor with PAE (version 5.0 and higher)\n");
     } else
     if(!strcmp("ntkrpamp.pdb", (char*)pdb_header->pdb_file_name)) {
        printf("\tMulti-processor with PAE (version 5.0 and higher)\n");
     }

done:
    free(pdb_header);
}

void print_pe_header(vmi_instance_t vmi, addr_t image_base_p, uint8_t *pe) {

    struct pe_header *pe_header = NULL;
    struct dos_header *dos_header = NULL;
    uint16_t optional_header_type = 0;
    peparse_assign_headers(pe, &dos_header, &pe_header, &optional_header_type, NULL, NULL, NULL);

    printf("\tSignature: %u.\n", pe_header->signature);
    printf("\tMachine: %u.\n", pe_header->machine);
    printf("\t# of sections: %u.\n", pe_header->number_of_sections);
    printf("\t# of symbols: %u.\n", pe_header->number_of_symbols);
    printf("\tTimestamp: %u.\n", pe_header->time_date_stamp);
    printf("\tCharacteristics: %u.\n", pe_header->characteristics);
    printf("\tOptional header size: %u.\n", pe_header->size_of_optional_header);
    printf("\tOptional header type: 0x%x\n", optional_header_type);

    uint32_t c;
    for(c=0; c < pe_header->number_of_sections; c++) {

        struct section_header section;
        addr_t section_addr = image_base_p
            + dos_header->offset_to_pe
            + sizeof(struct pe_header)
            + pe_header->size_of_optional_header
            + c*sizeof(struct section_header);

        // Read the section from memory
        if ( sizeof(struct section_header) != vmi_read_pa(vmi, section_addr, (uint8_t *)&section, sizeof(struct section_header)) )
            return;

        // The character array is not null terminated, so only print the first 8 characters!
        printf("\tSection %u: %.8s\n", c+1, section.short_name);
    }
}

int main(int argc, char **argv) {

    vmi_instance_t vmi;

    /* this is the VM that we are looking at */
    if (argc != 3) {
        printf("Usage: %s name|domid <domain name|domain id>\n", argv[0]);
        return 1;
    }   // if

    uint64_t domid = VMI_INVALID_DOMID;
    GHashTable *config = g_hash_table_new(g_str_hash, g_str_equal);

    if(strcmp(argv[1],"name")==0) {
        g_hash_table_insert(config, "name", argv[2]);
    } else
    if(strcmp(argv[1],"domid")==0) {
        domid = strtoull(argv[2], NULL, 0);
        g_hash_table_insert(config, "domid", &domid);
    } else {
        printf("You have to specify either name or domid!\n");
        return 1;
    }

    /* partialy initialize the libvmi library */
    if (vmi_init_custom(&vmi, VMI_AUTO | VMI_INIT_PARTIAL | VMI_CONFIG_GHASHTABLE, config) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        g_hash_table_destroy(config);
        return 1;
    }
    g_hash_table_destroy(config);

    max_mem = vmi_get_max_physical_address(vmi);

    /* the nice thing about the windows kernel is that it's page aligned */
    uint32_t found = 0;
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_NONE,
    };

    for(ctx.addr = 0; ctx.addr < max_mem; ctx.addr += PAGE_SIZE) {

        uint8_t pe[MAX_HEADER_SIZE];

        if(VMI_SUCCESS == peparse_get_image(vmi, &ctx, MAX_HEADER_SIZE, pe)) {
            if(VMI_SUCCESS == is_WINDOWS_KERNEL(vmi, ctx.addr, pe)) {

                printf("Windows Kernel found @ 0x%" PRIx64 "\n", ctx.addr);
                print_os_version(pe);
                print_guid(vmi, ctx.addr, pe);
                print_pe_header(vmi, ctx.addr, pe);
                found=1;
                break;
            }
        }
    }

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    if(found) return 0;
    return 1;
}

/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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

#include "private.h"

#define _GNU_SOURCE

#include <string.h>
#include "os/osx/osx.h"
#include "private.h"

#define MAX_ROW_LENGTH 500


static bool in_segment(osx_segment_t *seg, const uint64_t file_address)
{
    return seg->fstart < file_address && file_address < seg->fend;
}


status_t
osx_symbol_to_address(
    vmi_instance_t vmi,
    const char *symbol,
    addr_t *UNUSED(__unused),
    addr_t *address)
{

    /* In addition to search symbol in profile, this function will resolve any memory mapping issue and return the actual virtual address*/
    osx_instance_t osx_instance = vmi->os_data;
    osx_mapping_t *k_mmap;
    uint64_t file_address = 0;
    status_t status = VMI_FAILURE;

    CHECK((osx_instance != NULL));
    CHECK((osx_instance->k_mmap.segments != NULL));
    CHECK(json_profile(vmi));

    CHECK_SUCCESS(json_profile_lookup(vmi, symbol, NULL, &file_address));

    k_mmap = &osx_instance->k_mmap;
    for (uint32_t i = 0; i < k_mmap->count; i++) {
        if (!in_segment(&k_mmap->segments[i], file_address)) {
            continue;
        }
        *address = k_mmap->segments[i].mstart + (file_address - k_mmap->segments[i].fstart);
        dbprint(VMI_DEBUG_OSX, "Found %s in %s | [0x%"PRIx64"]->[0x%"PRIx64"]\n", symbol, k_mmap->segments[i].name,
                file_address, *address);

        status = VMI_SUCCESS;
        break;
    }

done:
    return status;
}

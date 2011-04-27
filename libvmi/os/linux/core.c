/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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

#include "libvmi.h"
#include "private.h"
#include "driver/interface.h"

status_t linux_init (vmi_instance_t vmi)
{
    int ret = VMI_FAILURE;
    unsigned char *memory = NULL;
    uint32_t local_offset = 0;

    if (linux_system_map_symbol_to_address(
             vmi, "swapper_pg_dir", &vmi->kpgd) == VMI_FAILURE){
        errprint("Failed to lookup 'swapper_pg_dir' address.\n");
        goto error_exit;
    }
    dbprint("--got vaddr for swapper_pg_dir (0x%.8x).\n", vmi->kpgd);

    if (driver_is_pv(vmi)){
        vmi->kpgd -= vmi->page_offset;
        if (vmi_read_32_pa(
                vmi, vmi->kpgd, &(vmi->kpgd)) == VMI_FAILURE){
            errprint("Failed to get physical addr for kpgd.\n");
            goto error_exit;
        }
    }
    dbprint("**set vmi->kpgd (0x%.8x).\n", vmi->kpgd);

    addr_t address = vmi_translate_ksym2v(vmi, "init_task");
    address += vmi->os.linux_instance.tasks_offset;
    if (VMI_FAILURE == vmi_read_32_va(vmi, address, 0, &(vmi->init_task))){
        dbprint("--address lookup failure, switching PAE mode\n");
        vmi->pae = !vmi->pae;
        dbprint("**set pae = %d\n", vmi->pae);
        if (VMI_FAILURE == vmi_read_32_va(vmi, address, 0, &(vmi->init_task))){
            errprint("Failed to get task list head 'init_task'.\n");
            goto error_exit;
        }
    }

    ret = VMI_SUCCESS;
error_exit:
    return ret;
}

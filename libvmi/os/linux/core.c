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

#include "libvmi.h"
#include "private.h"
#include "driver/interface.h"

status_t
linux_init(
    vmi_instance_t vmi)
{
    status_t ret = VMI_FAILURE;

    if (vmi->cr3) {
        vmi->kpgd = vmi->cr3;
    }
    else if (VMI_SUCCESS ==
             linux_system_map_symbol_to_address(vmi, "swapper_pg_dir",
                                                &vmi->kpgd)) {
        dbprint("--got vaddr for swapper_pg_dir (0x%.16"PRIx64").\n",
                vmi->kpgd);
        if (driver_is_pv(vmi)) {
            vmi->kpgd = vmi_translate_kv2p(vmi, vmi->kpgd);
            if (vmi_read_addr_pa(vmi, vmi->kpgd, &(vmi->kpgd)) ==
                VMI_FAILURE) {
                errprint("Failed to get physical addr for kpgd.\n");
                goto _exit;
            }
        }
        else {
            vmi->kpgd = vmi_translate_kv2p(vmi, vmi->kpgd);
        }
    }
    else {
        errprint("swapper_pg_dir not found and CR3 not set, exiting\n");
        goto _exit;
    }

    vmi->kpgd = vmi->cr3;
    dbprint("**set vmi->kpgd (0x%.16"PRIx64").\n", vmi->kpgd);

    addr_t address = vmi_translate_ksym2v(vmi, "init_task");

    address += vmi->os.linux_instance.tasks_offset;
    if (VMI_FAILURE ==
        vmi_read_addr_va(vmi, address, 0, &(vmi->init_task))) {
        errprint("Failed to get task list head 'init_task'.\n");
        goto _exit;
    }

    ret = VMI_SUCCESS;
_exit:
    return ret;
}

/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel <tamas.lengyel@zentific.com>
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

#include <string.h>

#include "xen_private.h"

static inline status_t sanity_check(xen_instance_t *xen)
{
    status_t ret = VMI_FAILURE;
    libxc_wrapper_t *w = &xen->libxcw;

    if ( xen->major_version != 4 )
        return ret;

    switch ( xen->minor_version )
    {
        case 1:
            if ( !w->xc_domain_maximum_gpfn )
                break;

            ret = VMI_SUCCESS;
            break;
        case 2:
        case 3:
        case 4:
            if ( !w->xc_domain_maximum_gpfn || !w->xc_map_foreign_batch ||
                 !w->xc_mem_access_enable || !w->xc_mem_access_disable ||
                 !w->xc_mem_access_resume || !w->xc_hvm_set_mem_access ||
                 !w->xc_hvm_get_mem_access )
                break;

            ret = VMI_SUCCESS;
            break;

        case 5:
            if ( !w->xc_domain_maximum_gpfn || !w->xc_set_mem_access ||
                 !w->xc_get_mem_access || !w->xc_mem_access_enable2 ||
                 !w->xc_mem_access_disable || !w->xc_mem_access_disable )
                break;

            ret = VMI_SUCCESS;
            break;

        /* Things start to be a bit saner from 4.6 */
        case 8:
            if ( !w->xc_monitor_debug_exceptions || !w->xc_monitor_cpuid )
                break;
            /* Fall-through */
        case 7:
            /* Fall-through */
        case 6:
            if ( !w->xc_domain_maximum_gpfn2 || !w->xc_set_mem_access ||
                 !w->xc_get_mem_access || !w->xc_monitor_enable ||
                 !w->xc_monitor_disable || !w->xc_monitor_resume ||
                 !w->xc_monitor_get_capabilities || !w->xc_monitor_write_ctrlreg ||
                 !w->xc_monitor_mov_to_msr || !w->xc_monitor_singlestep ||
                 !w->xc_monitor_software_breakpoint || !w->xc_monitor_guest_request ||
                 !w->xc_altp2m_get_domain_state || !w->xc_altp2m_set_domain_state ||
                 !w->xc_altp2m_set_vcpu_enable_notify || !w->xc_altp2m_create_view ||
                 !w->xc_altp2m_destroy_view || !w->xc_altp2m_switch_to_view ||
                 !w->xc_altp2m_set_mem_access || !w->xc_altp2m_change_gfn )
                break;

            ret = VMI_SUCCESS;
            break;
        default:
            break;
    };

    return ret;
}

status_t create_libxc_wrapper(xen_instance_t *xen)
{
    libxc_wrapper_t *wrapper = &xen->libxcw;

    memset ( wrapper, 0, sizeof(libxc_wrapper_t) );

    wrapper->handle = dlopen ("libxenctrl.so", RTLD_NOW | RTLD_GLOBAL);

    if ( !wrapper->handle )
    {
        char *alternate = g_malloc0(snprintf(NULL, 0, "libxenctrl.so.%u.%u",
                                             xen->major_version, xen->minor_version)+1);
        sprintf(alternate, "libxenctrl.so.%u.%u", xen->major_version, xen->minor_version);

        dbprint(VMI_DEBUG_XEN, "--libxc_wrapper looking for %s\n", alternate);

        wrapper->handle = dlopen (alternate, RTLD_NOW | RTLD_GLOBAL);
        g_free(alternate);

        if ( !wrapper->handle )
        {
            fprintf(stderr, "Failed to find a suitable libxenctrl.so at any of the standard paths!\n");
            return VMI_FAILURE;
        }
    }

    wrapper->xc_domain_maximum_gpfn = dlsym(wrapper->handle, "xc_domain_maximum_gpfn");
    wrapper->xc_domain_maximum_gpfn2 = dlsym(wrapper->handle, "xc_domain_maximum_gpfn");
    wrapper->xc_map_foreign_batch = dlsym(wrapper->handle, "xc_map_foreign_batch");
    wrapper->xc_hvm_set_mem_access = dlsym(wrapper->handle, "xc_hvm_set_mem_access");
    wrapper->xc_hvm_get_mem_access = dlsym(wrapper->handle, "xc_hvm_get_mem_access");
    wrapper->xc_set_mem_access = dlsym(wrapper->handle, "xc_set_mem_access");
    wrapper->xc_get_mem_access = dlsym(wrapper->handle, "xc_get_mem_access");
    wrapper->xc_mem_access_enable = dlsym(wrapper->handle, "xc_mem_access_enable");
    wrapper->xc_mem_access_enable2 = dlsym(wrapper->handle, "xc_mem_access_enable");
    wrapper->xc_mem_access_disable = dlsym(wrapper->handle, "xc_mem_access_disable");
    wrapper->xc_mem_access_resume = dlsym(wrapper->handle, "xc_mem_access_resume");
    wrapper->xc_monitor_enable = dlsym(wrapper->handle, "xc_monitor_enable");
    wrapper->xc_monitor_disable = dlsym(wrapper->handle, "xc_monitor_disable");
    wrapper->xc_monitor_resume = dlsym(wrapper->handle, "xc_monitor_resume");
    wrapper->xc_monitor_get_capabilities = dlsym(wrapper->handle, "xc_monitor_get_capabilities");
    wrapper->xc_monitor_write_ctrlreg = dlsym(wrapper->handle, "xc_monitor_write_ctrlreg");
    wrapper->xc_monitor_mov_to_msr = dlsym(wrapper->handle, "xc_monitor_mov_to_msr");
    wrapper->xc_monitor_singlestep = dlsym(wrapper->handle, "xc_monitor_singlestep");
    wrapper->xc_monitor_software_breakpoint = dlsym(wrapper->handle, "xc_monitor_software_breakpoint");
    wrapper->xc_monitor_guest_request = dlsym(wrapper->handle, "xc_monitor_guest_request");
    wrapper->xc_altp2m_get_domain_state = dlsym ( wrapper->handle , "xc_altp2m_get_domain_state" );
    wrapper->xc_altp2m_set_domain_state = dlsym ( wrapper->handle , "xc_altp2m_set_domain_state" );
    wrapper->xc_altp2m_set_vcpu_enable_notify = dlsym ( wrapper->handle , "xc_altp2m_set_vcpu_enable_notify" );
    wrapper->xc_altp2m_create_view = dlsym ( wrapper->handle , "xc_altp2m_create_view" );
    wrapper->xc_altp2m_destroy_view = dlsym(wrapper->handle, "xc_altp2m_destroy_view");
    wrapper->xc_altp2m_switch_to_view = dlsym ( wrapper->handle , "xc_altp2m_switch_to_view" );
    wrapper->xc_altp2m_set_mem_access = dlsym ( wrapper->handle , "xc_altp2m_set_mem_access" );
    wrapper->xc_altp2m_change_gfn = dlsym ( wrapper->handle , "xc_altp2m_change_gfn" );
    wrapper->xc_monitor_debug_exceptions = dlsym(wrapper->handle, "xc_monitor_debug_exceptions");
    wrapper->xc_monitor_cpuid = dlsym(wrapper->handle, "xc_monitor_cpuid");

    return sanity_check(xen);
}

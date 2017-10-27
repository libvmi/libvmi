/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * Author: Tamas K Lengyel (tamas@tklengyel.com)
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

#include "private.h"
#include "driver/xen/xen.h"
#include "driver/xen/xen_private.h"
#include "driver/xen/xen_events.h"
#include "driver/xen/xen_events_private.h"

status_t wait_for_event_or_timeout(xen_instance_t *xen, xc_evtchn *xce, unsigned long ms)
{
    struct pollfd fd = {
        .fd = xen->libxcw.xc_evtchn_fd(xce),
        .events = POLLIN | POLLERR
    };

    switch ( poll(&fd, 1, ms) ) {
        case -1:
            if (errno == EINTR)
                return VMI_SUCCESS;

            errprint("Poll exited with an error\n");
            return VMI_FAILURE;
        case 0:
            return VMI_SUCCESS;
        default: {
            int port = xen->libxcw.xc_evtchn_pending(xce);
            if ( -1 == port ) {
                errprint("Failed to read port from event channel\n");
                return VMI_FAILURE;
            }

            if ( xen->libxcw.xc_evtchn_unmask(xce, port) ) {
                errprint("Failed to unmask event channel port\n");
                return VMI_FAILURE;
            }

            return VMI_SUCCESS;
        }
    };

    return VMI_FAILURE;
}

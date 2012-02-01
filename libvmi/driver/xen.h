/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
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

#if ENABLE_XEN == 1
#include <xenctrl.h>

typedef struct xen_instance{
#ifdef XENCTRL_HAS_XC_INTERFACE // Xen >= 4.1
    xc_interface *xchandle; /**< handle to xenctrl library (libxc) */
#else
    int xchandle;           /**< handle to xenctrl library (libxc) */
#endif
    unsigned long domainid; /**< domid that we are accessing */
    int xen_version;        /**< version of Xen libxa is running on */
    int hvm;                /**< nonzero if HVM memory image */
    xc_dominfo_t info;      /**< libxc info: domid, ssidref, stats, etc */
    unsigned long *live_pfn_to_mfn_table;
    unsigned long nr_pfns;
    char *name;
} xen_instance_t;

#else

typedef struct xen_instance{
} xen_instance_t;

#endif /* ENABLE_XEN */

status_t xen_init (vmi_instance_t vmi);
void xen_destroy (vmi_instance_t vmi);
unsigned long xen_get_domainid_from_name (vmi_instance_t vmi, char *name);
unsigned long xen_get_domainid (vmi_instance_t vmi);
void xen_set_domainid (vmi_instance_t vmi, unsigned long domainid);
status_t xen_get_domainname (vmi_instance_t vmi, char **name);
void xen_set_domainname (vmi_instance_t vmi, char *name);
status_t xen_get_memsize (vmi_instance_t vmi, unsigned long *size);
status_t xen_get_vcpureg (vmi_instance_t vmi, reg_t *value, registers_t reg, unsigned long vcpu);
status_t xen_get_address_width (vmi_instance_t vmi, uint8_t * width_in_bytes);
addr_t xen_pfn_to_mfn (vmi_instance_t vmi, addr_t pfn);
void *xen_read_page (vmi_instance_t vmi, addr_t page);
status_t xen_write (vmi_instance_t vmi, addr_t paddr, void *buf, uint32_t length);
int xen_is_pv (vmi_instance_t vmi);
status_t xen_test (unsigned long id, char *name);
status_t xen_pause_vm (vmi_instance_t vmi);
status_t xen_resume_vm (vmi_instance_t vmi);

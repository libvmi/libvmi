/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
 * Author: Dorian Eikenberg (dorian.eikenberg@gdata.de)
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

#include <errno.h>
#include <string.h>
#include "private.h"
#include "kvm_slat.h"

status_t kvm_slat_state(vmi_instance_t vmi, bool *state)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    if (kvm->libkvmi.kvmi_eptp_support(kvm->kvmi_dom, state)) {
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

// We cannot control the SLAT feature, but we should at least return VMI_FAILURE
// if someone tries to enable it while ept support is not present.
status_t kvm_slat_control(vmi_instance_t vmi, bool state)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    if (!state) {
        return VMI_SUCCESS;
    }

    bool ept_support = false;
    kvm_slat_state(vmi, &ept_support);

    if (ept_support) {
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

status_t kvm_create_view(vmi_instance_t vmi, uint16_t *view)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    if (kvm->libkvmi.kvmi_create_ept_view(kvm->kvmi_dom, view)) {
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t kvm_destroy_view(vmi_instance_t vmi, uint16_t view)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    if (kvm->libkvmi.kvmi_destroy_ept_view(kvm->kvmi_dom, view)) {
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t kvm_switch_view(vmi_instance_t vmi, uint16_t view)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    status_t ret = VMI_SUCCESS;
    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        if (kvm->libkvmi.kvmi_switch_ept_view(kvm->kvmi_dom, vcpu, view)) {
            errprint("%s: unable to switch to view %d for vcpu %d\n", __func__, view, vcpu);
            ret = VMI_FAILURE;
        }
    }

    return ret;
}

status_t kvm_change_gfn(vmi_instance_t vmi,
                        uint16_t slat_idx,
                        addr_t old_gfn,
                        addr_t new_gfn)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif
    kvm_instance_t *kvm = kvm_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if (!kvm || !kvm->kvmi_dom) {
        errprint("%s: invalid kvm handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        int ret;
        do {
            ret = kvm->libkvmi.kvmi_change_gfn(kvm->kvmi_dom, vcpu, slat_idx, old_gfn, new_gfn);
        } while (ret != 0 && errno == EAGAIN);

        if (ret != 0) {
            errprint("%s: unable to change gfn mapping. ERRNO: %s\n", __func__, strerror(errno));
            return VMI_FAILURE;
        }
    }

    return VMI_SUCCESS;
}

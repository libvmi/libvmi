/* The LibVMI Library is an introspection library that simplifies access to
* memory in a target virtual machine or in a file containing a dump of
* a system's physical memory.  LibVMI is based on the XenAccess Library.
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

/**
* @file vbd.h
* @brief The functions and structures concerning virtual block devices reading
* and description are defined here.
*
*/

#ifndef VBD_H
#define VBD_H

typedef enum vbd_device_type {
    VBD_DEVICE_TYPE_DISK    = 1,
    VBD_DEVICE_TYPE_CDROM   = 2,
    VBD_DEVICE_TYPE_UNKNOWN = -1
} vbd_device_type_t;

typedef enum vbd_backend_type {
    VBD_BACKEND_TYPE_PHY     = 1,
    VBD_BACKEND_TYPE_QDISK   = 2,
    VBD_BACKEND_TYPE_UNKNOWN = -1
} vbd_backend_type_t;

typedef enum vbd_backend_format {
    VBD_BACKEND_FORMAT_RAW     = 1,
    VBD_BACKEND_FORMAT_QCOW2   = 2,
    VBD_BACKEND_FORMAT_VHD     = 3,
    VBD_BACKEND_FORMAT_UNKNOWN = -1
} vbd_backend_format_t;

typedef struct {
    vbd_backend_type_t    type;                   // phy, qdisk
    vbd_backend_format_t  format;                 // raw, qcow2, vhd
    bool                  bootable;               // is device bootable, according to XenStore item property
    char                  path[0x1000];           // xs path /local/domain/<dom0_ID>/backend/<type>/<domId>/<devId>
} vbd_backend_t;

typedef struct {
    vbd_device_type_t  type;                      // cdrom, disk...
    vbd_backend_t      backend;                   // host device or file
    char               devId[0x100];              // numeric str
    char               path[0x1000];              // xs path - /local/domain/<domId>/device/vbd/<devId>
} vbd_t;

status_t vbd_read_raw_disk(vmi_instance_t vmi, const char* backend_path, uint64_t offset, uint64_t count, void *buffer);

#ifdef HAVE_ZLIB
status_t vbd_read_qcow2_disk(vmi_instance_t vmi, const char* backend_path, uint64_t offset, uint64_t count, void *buffer);
#else
static inline status_t
vbd_read_qcow2_disk(vmi_instance_t UNUSED(vmi), const char* UNUSED(backend_path), uint64_t UNUSED(offset), uint64_t UNUSED(count), void *UNUSED(buffer))
{
    errprint("VMI_ERROR: vbd_read_qcow2_disk: failed to read QCOW2 disk, ZLIB is required\n");
    return VMI_FAILURE;
}
#endif

#endif

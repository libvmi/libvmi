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

#ifndef FILE_PRIVATE_H
#define FILE_PRIVATE_H

#include "private.h"
#include "driver/file/file.h"

typedef struct file_instance {

    FILE *fhandle;       /**< handle to the memory image file */

    int fd;              /**< file descriptor to the memory image file */

    char *filename;      /**< name of the file being accessed */

    void *map;           /**< memory mapped file */
} file_instance_t;

static inline file_instance_t*
file_get_instance(vmi_instance_t vmi)
{
    return ((file_instance_t *) vmi->driver.driver_data);
}

#endif /* FILE_PRIVATE_H */

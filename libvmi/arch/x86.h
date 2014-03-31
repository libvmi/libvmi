/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
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

#ifndef X86_H
#define X86_H

#include "libvmi.h"
#include "private.h"
#include "driver/interface.h"
#include <stdlib.h>
#include <sys/mman.h>

#define PTRS_PER_PDPI 4
#define PTRS_PER_PAE_PTE 512
#define PTRS_PER_PAE_PGD 512

/* bit flag testing */
#define ENTRY_PRESENT(os_type, entry) \
    (VMI_GET_BIT(entry, 0) \
        ? 1 : \
        ( \
            (os_type == VMI_OS_WINDOWS && \
                (VMI_GET_BIT(entry, 11) && !(VMI_GET_BIT(entry, 10))) \
            ) \
            ? 1 : 0 \
        ) \
    )

#define PAGE_SIZE_FLAG(entry) VMI_GET_BIT(entry, 7)

#endif

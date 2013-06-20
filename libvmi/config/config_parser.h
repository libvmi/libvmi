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
 
#include "../libvmi.h"

#ifndef CONFIG_PARSER_H_
#define CONFIG_PARSER_H_

#define CONFIG_STR_LENGTH 1024

typedef struct vmi_config_entry {
    char domain_name[CONFIG_STR_LENGTH];
    char sysmap[CONFIG_STR_LENGTH];
    char ostype[CONFIG_STR_LENGTH];
    union {
        struct linux_offsets {
            int tasks;
            int mm;
            int pid;
            int pgd;
            int addr; 
            int name;
        } linux_offsets;
        struct windows_offsets {
            int ntoskrnl;
            int tasks; 
            int pdbase;
            int pid;
            int peb;
            int iba;
            int ph;
            int pname;
            uint64_t kdvb;
            uint64_t sysproc;
        } windows_offsets;
    } offsets;
} vmi_config_entry_t;

int vmi_parse_config(char *td);
vmi_config_entry_t* vmi_get_config();

#endif /* CONFIG_PARSER_H_ */

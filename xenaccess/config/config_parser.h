/*
 * The libxa library provides access to resources in domU machines.
 *
 * Copyright (C) 2005 - 2007  Bryan D. Payne (bryan@thepaynes.cc)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * --------------------
 * Data structures and functions for passing configuration file info
 * to the rest of the XenAccess library.
 *
 * File: config.h
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 *
 * $Id$
 * $Date$
 */
#include "../xenaccess.h"

#define CONFIG_STR_LENGTH 1024

typedef struct xa_config_entry {
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
        } linux_offsets;
        struct windows_offsets {
            int ntoskrnl;
            int tasks; 
            int pdbase;
            int pid;
            int peb;
            int iba;
            int ph;
        } windows_offsets;
    } offsets;
} xa_config_entry_t;

int xa_parse_config(char *td);
xa_config_entry_t* xa_get_config();

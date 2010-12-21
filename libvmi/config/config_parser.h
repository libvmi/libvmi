/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */
 
#include "../libvmi.h"

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
} vmi_config_entry_t;

int vmi_parse_config(char *td);
vmi_config_entry_t* vmi_get_config();

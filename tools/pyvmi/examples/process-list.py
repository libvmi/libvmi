#!/usr/bin/env python
"""
The LibVMI Library is an introspection library that simplifies access to 
memory in a target virtual machine or in a file containing a dump of 
a system's physical memory.  LibVMI is based on the XenAccess Library.

Copyright (C) 2011 Sandia National Laboratories
Author: Bryan D. Payne (bpayne@sandia.gov)

This file is part of LibVMI.

LibVMI is free software: you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

LibVMI is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.

You should have received a copy of the GNU Lesser General Public License
along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
"""

import pyvmi
import struct
import sys

def val_int (value):
    return struct.unpack("i", value)[0]

def val_uint (value):
    return struct.unpack("I", value)[0]

def process_list(vmi):
    tasks_offset = vmi.get_offset("win_tasks")
    name_offset = vmi.get_offset("win_pname")
    pid_offset = vmi.get_offset("win_pid")

    list_head = val_uint(vmi.read_32_ksym("PsInitialSystemProcess"))
    next_process = val_uint(vmi.read_32_va(list_head + tasks_offset, 0))
    pid = val_int(vmi.read_32_va(list_head + pid_offset, 0))
    procname = vmi.read_str_va(list_head + name_offset, 0)
    print "[%5d] %s" % (pid, procname)

    list_head = next_process
    while 1:
        tmp_next = val_uint(vmi.read_32_va(next_process, 0))
        if (list_head == tmp_next):
            break
        procname = vmi.read_str_va(next_process + name_offset - tasks_offset, 0)
        pid = val_int(vmi.read_32_va(next_process + pid_offset - tasks_offset, 0))

        if (pid >= 0):
            print "[%5d] %s" % (pid, procname)
        next_process = tmp_next

def main (argv):
    vmi = pyvmi.init(argv[1], "complete")
    process_list(vmi)

if __name__ == "__main__":
    main(sys.argv)


#!/usr/bin/env python
"""
The LibVMI Library is an introspection library that simplifies access to 
memory in a target virtual machine or in a file containing a dump of 
a system's physical memory.  LibVMI is based on the XenAccess Library.

Copyright 2011 Sandia Corporation. Under the terms of Contract
DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
retains certain rights in this software.

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

from __future__ import with_statement

with open('kpcr.c', 'r') as f:
    inside = 0
    for line in f:
        if line.startswith('struct _KDDEBUGGER_DATA64'):
            inside = 1
        elif inside and line.startswith('} __attribute__ ((packed));'):
            inside = 0
        elif inside and line.startswith('    uint64_t'):
            fields = line.split()
            fields = fields[1].split(';')
            varname = fields[0]
            print """    else if (strncmp(symbol, "%s", max_symbol_length) == 0){
        *offset = (unsigned long)(&(d.%s)) - (unsigned long)(&d);
    }""" % (varname, varname)

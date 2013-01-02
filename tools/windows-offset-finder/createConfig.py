#!/usr/bin/env python
"""
The LibVMI Library is an introspection library that simplifies access to 
memory in a target virtual machine or in a file containing a dump of 
a system's physical memory.  LibVMI is based on the XenAccess Library.

Copyright 2011 Sandia Corporation. Under the terms of Contract
DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
retains certain rights in this software.

Authors: Daniel English and John Maccini

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

import os.path, sys, os, urllib2

def configfromdump(filename):
    config = "<vm name> {\n"
    config += '    ostype = "Windows";\n'
    with open(filename, 'r') as f:
        for line in f:
            line  = line.strip("\r\n")
            lineSplit = line.split(',')
            if len(lineSplit) >3:
                if lineSplit[0] == "_EPROCESS" and lineSplit[1] == "ActiveProcessLinks":
                    tasks = "    win_tasks   = "+ lineSplit[2]+ ';\n'
                elif lineSplit[0] == "_KPROCESS" and lineSplit[1] == "DirectoryTableBase":
                    base = "    win_pdbase  = "+ lineSplit[2]+ ';\n'
                elif lineSplit[0] == "_EPROCESS"  and lineSplit[1] == "UniqueProcessId":
                    pid = "    win_pid     = "+ lineSplit[2]+';\n'
                elif lineSplit[0] == "_EPROCESS"  and lineSplit[1] == "ImageFileName":
                    pname = "    win_pname   = "+ lineSplit[2]+';\n'
    config += tasks + base + pid + pname
    config += "}"
    print config

def main():
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option('-f', '--file', dest='infile',
        help='Input file, this is the output from dumpPDB.py [required]')
    opts,args = parser.parse_args()
    if opts.infile:
        configfromdump(opts.infile)
    else:
        print "Must supply an input filename.  Use -h for help"
        sys.exit(0)

if __name__ == "__main__":
    main()

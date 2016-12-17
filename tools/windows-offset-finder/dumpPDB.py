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

---
This program dumps the data contained in a supplied PDB file to a comma-
separated-values text file. It requires the open-source PDBParse library
and is based heavily on the example code included in that library.

Input consists of a PDB file, specified either from the command line or 
from stdin (used in a pipe). Output is placed in a text file specified
on the command line.
---

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

import urllib2
import sys,os
import pdbparse
import os.path


ctype  = {
    "T_32PINT4": "pointer to long",
    "T_32PRCHAR": "pointer to unsigned char",
    "T_32PUCHAR": "pointer to unsigned char",
    "T_32PULONG": "pointer to unsigned long",
    "T_32PLONG": "pointer to long",
    "T_32PUQUAD": "pointer to unsigned long long",
    "T_32PUSHORT": "pointer to unsigned short",
    "T_32PVOID": "pointer to void",
    "T_64PVOID": "pointer64 to void",
    "T_INT4": "long",
    "T_INT8": "long long",
    "T_LONG": "long",
    "T_QUAD": "long long",
    "T_RCHAR": "unsigned char",
    "T_REAL32": "float",
    "T_REAL64": "double",
    "T_REAL80": "long double",
    "T_SHORT": "short",
    "T_UCHAR": "unsigned char",
    "T_UINT4": "unsigned long",
    "T_ULONG": "unsigned long",
    "T_UQUAD": "unsigned long long",
    "T_USHORT": "unsigned short",
    "T_WCHAR": "wchar",
    "T_VOID": "void",
}

base_type_size = {
    "T_32PRCHAR": 4,
    "T_32PUCHAR": 4,
    "T_32PULONG": 4,
    "T_32PUQUAD": 4,
    "T_32PUSHORT": 4,
    "T_32PVOID": 4,
    "T_64PVOID": 8,
    "T_INT4": 4,
    "T_INT8": 8,
    "T_LONG": 4,
    "T_QUAD": 8,
    "T_RCHAR": 1,
    "T_REAL32": 4,
    "T_REAL64": 8,
    "T_REAL80": 10,
    "T_SHORT": 2,
    "T_UCHAR": 1,
    "T_UINT4": 4,
    "T_ULONG": 4,
    "T_UQUAD": 8,
    "T_USHORT": 2,
    "T_WCHAR": 2,
    "T_32PLONG": 4,
}

def get_size(lf):
    if isinstance(lf,str):
        return base_type_size[lf]
    elif (lf.leaf_type == "LF_STRUCTURE" or
          lf.leaf_type == "LF_ARRAY" or
          lf.leaf_type == "LF_UNION"):
        return lf.size
    elif lf.leaf_type == "LF_POINTER":
        return 4 
    elif lf.leaf_type == "LF_MODIFIER":
        return get_size(lf.modified_type)
    else: return -1


def get_tpname(lf):
    if isinstance(lf, str):
        try: tpname = ctype[lf]
        except KeyError: tpname = lf
    elif lf.leaf_type == "LF_STRUCTURE": tpname = lf.name
    elif lf.leaf_type == "LF_ENUM": tpname = lf.name
    elif lf.leaf_type == "LF_UNION": tpname = lf.name
    elif lf.leaf_type == "LF_POINTER": tpname = ptr_str(lf)
    elif lf.leaf_type == "LF_PROCEDURE": tpname = proc_str(lf)
    elif lf.leaf_type == "LF_MODIFIER": tpname = mod_str(lf)
    elif lf.leaf_type == "LF_ARRAY": tpname = arr_str(lf)
    elif lf.leaf_type == "LF_BITFIELD": tpname = bit_str(lf)
    else: tpname = lf.leaf_type
    return tpname

def ptr_str(ptr):
    tpname = get_tpname(ptr.utype)
    return "pointer to %s" % tpname

def proc_str(proc):
    argstrs = []
    for a in proc.arglist.arg_type:
        argstrs.append(get_tpname(a))
    return "function(%s)" % ", ".join(argstrs)

def bit_str(bitf):
    return "bitfield pos: %d len: %d [%s]" % (bitf.position, bitf.length, get_tpname(bitf.base_type))

def arr_str(arr):
    tpname = get_tpname(arr.element_type)
    count = arr.size / get_size(arr.element_type)
    return "array %s[%d]" % (tpname, count)

def mod_str(mod):
    tpname = get_tpname(mod.modified_type)
    modifiers = [ m for m in ["const","unaligned","volatile"] if mod.modifier[m]]
    return "%s %s" % (" ".join(modifiers), tpname)


#Purpose: Create a comma-separated-values file containing all of the type output from the PDB file.
#
#Inputs: pdbFile: path to the pdbfile to be dumped
#	filename: filename for dump file
#
#Outputs: Results in the creation of a .txt file containing the types in the PDB file.
def dump_types(pdbFile, filename):
	pdb = pdbparse.parse(pdbFile) #call the parse function in __init__ of the pdbparse library
	structs = [ s for s in pdb.streams[2].types.values() if (s.leaf_type == "LF_STRUCTURE" or s.leaf_type == "LF_UNION") and not s.prop.fwdref ]


	FILE=open(filename, "w"); #open filename in write mode
	FILE.write(pdbFile[:-4] +' (pdb file)' + "\n") # put the OS version at the top of the file!
	for s in structs:
		FILE.write(s.name + "," + s.name + "," + ("%#x" % s.size) + "," + "struct\n")
		for f in s.fieldlist.substructs:
			tpname =get_tpname(f.index)
			FILE.write(s.name + "," + f.name + "," + str(hex(f.offset)) + "," + "%s" % (tpname) + "\n")

	FILE.close()


def main():
	from optparse import OptionParser
	parser = OptionParser()
	parser.add_option('-f', '--file', dest='infile',
		help='specify input PDB file [required unless piped with downloadPDB.py (no verbose flag)]')
	parser.add_option('-o','--outfile',dest='outfile', help='Must supply an output filename.')
	opts,args = parser.parse_args()
	if opts.outfile:
		if opts.infile: #if -f option is provided, use that filename
			dump_types(opts.infile, opts.outfile)
		else: #otherwise use stdin (piped from downloadPDB.py)
			infile = sys.stdin.read().rstrip().split("\n")[-1].strip() #read stdin, strip out newline
			dump_types(infile, opts.outfile)
	else:
		print "Must supply an output filename.  Use -h for help"
		sys.exit(0)



if __name__ == "__main__":
	main()


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
This program uses a GUID and PDB file name (supplied by the user or through a pipe)
to access the Microsoft Symbol Server and download the associated PDB file. It heavily
uses functions from the open-source PDBParse library.

This program extracts the compressed PDB file and places it in the current directory.
The PDB filename is also displayed for use in pipes.

Dependencies: cabextract and msexpand (part of mscompress) must both be installed
for extraction of compressed files.

See README file for more information.
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
import os
import os.path
import sys
import urllib2

import pdbparse
from pefile import PE
from shutil import copyfileobj
from urllib import FancyURLopener
from pdbparse.dbgold import CV_RSDS_HEADER, CV_NB10_HEADER, DebugDirectoryType

#download_file function
#Purpose: download pdb file, when given a GUID and filename.
def download_file(guid,fname,verbose,path=""):
    '''
    Download the symbols specified by guid and filename. Note that 'guid'
    must be the GUID from the executable with the dashes removed *AND* the
    Age field appended. The resulting file will be saved to the path argument,
    which default to the current directory.
    '''

    url = "http://msdl.microsoft.com/download/symbols/%s/%s/" % (fname,guid.upper())

    types = [fname[:-1] + '_', fname]

    for saved_file in types:
      if verbose:
        print "Trying %s" % (url + saved_file)

      retval = os.system('curl %s --user-agent "Microsoft-Symbol-Server" %s --output %s' % ("" if verbose else "-s", url + saved_file, saved_file))

      if retval == 0:
        return saved_file

    return None

def error():
	print "Must pipe the output of getGUID into this program"
	sys.exit(0)


def main():
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option('-v', '--verbose', action="store_true", dest='verb',
            help='display loading bar and error messages')
    opts,args = parser.parse_args()

    if not sys.stdin.isatty():
        OSversion = sys.stdin.readline()
        x,y,OSversion = OSversion.partition(': ')
        OSversion=OSversion.strip('\r\n')
        OSversion = OSversion + ".pdb"
        inGuid = sys.stdin.readline()
        inGuid = sys.stdin.readline()
        x,y,inGuid = inGuid.partition(': ')
        inGuid=inGuid.strip('\r\n')
        inName = sys.stdin.readline()
        x,y,inName = inName.partition(': ')
        inName=inName.strip('\r\n')
        if inName == '':
            error()
        #print "OSversion: %s" % OSversion
        #print "Guid: %s" % inGuid
        #print "Name: %s" % inName
        #sys.exit(0)
        saved_file = download_file(inGuid,inName,opts.verb)
    else:
        error()
    if saved_file is not None:
        if saved_file.endswith("_"):
            # extrace compressed PDB
            retval = os.system(
                    'cabextract %s 1>/dev/null 2>/dev/null' % saved_file)
            if retval is not 0:
                # extract with msexpand if cabextract doesn't work
                os.system("msexpand %s 1>/dev/null" % saved_file)
                os.system("rm %s" % saved_file)
                os.system("mv %s %s" % (saved_file[:-1], OSversion))
            else:
                os.system("rm %s" % saved_file)
                savefile = saved_file[:-1] + 'b'
                os.system("mv %s %s" % (savefile, OSversion))
    print "%s" % OSversion


if __name__ == "__main__":
	main()

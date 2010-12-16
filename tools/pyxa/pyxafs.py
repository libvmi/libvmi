#!/usr/bin/env python

#    Copyright (C) 2009  Brendan Dolan-Gavitt <brendandg@gatech.edu>
#
#    A filesystem that allows access to a Xen domain's memory
# 
#    Based on the hello.py example distributed with FUSE-python, by
#    Copyright (C) 2006  Andrew Straw  <strawman@astraw.com>
#
#    This program can be distributed under the terms of the GNU LGPL.
#    See the file COPYING.
#

import os, stat, errno
# pull in some spaghetti to make this stuff work without fuse-py being installed
try:
    import _find_fuse_parts
except ImportError:
    pass
import fuse
from fuse import Fuse

if not hasattr(fuse, '__version__'):
    raise RuntimeError, \
        "your fuse-py doesn't know of fuse.__version__, probably it's too old."

fuse.fuse_python_api = (0, 2)

from pyxa import pyxa_instance

mem_path = '/mem'

class MyStat(fuse.Stat):
    def __init__(self):
        self.st_mode = 0
        self.st_ino = 0
        self.st_dev = 0
        self.st_nlink = 0
        self.st_uid = 0
        self.st_gid = 0
        self.st_size = 0
        self.st_atime = 0
        self.st_mtime = 0
        self.st_ctime = 0

class PyXaFS(Fuse):

    def getattr(self, path):
        st = MyStat()
        if path == '/':
            st.st_mode = stat.S_IFDIR | 0755
            st.st_nlink = 2
        elif path == mem_path:
            st.st_mode = stat.S_IFREG | 0444
            st.st_nlink = 1
            st.st_size = self.xai.get_size()
        else:
            return -errno.ENOENT
        return st

    def readdir(self, path, offset):
        for r in  '.', '..', mem_path[1:]:
            yield fuse.Direntry(r)

    def open(self, path, flags):
        if path != mem_path:
            return -errno.ENOENT
        accmode = os.O_RDONLY | os.O_WRONLY | os.O_RDWR
        if (flags & accmode) != os.O_RDONLY:
            return -errno.EACCES

    # PyXa reads a single page at a time. This function
    # allows reading an arbitrary range of physical memory
    # page by page.
    def zread(self, addr, length):
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((length + (addr % 0x1000)) / 0x1000) - 1
        left_over = (length + addr) % 0x1000
        
        if length < first_block:
            try:
                stuff_read = self.xai.read(addr)
            except ValueError:
                stuff_read = "\0" * 0x1000
            if stuff_read == None:
                return None
            return stuff_read[:length]

        try:
            stuff_read = self.xai.read(addr)
        except ValueError:
            stuff_read = "\0" * 0x1000
        if stuff_read == None:
            return None

        new_addr = addr + first_block
        for i in range(0,full_blocks):
            try:
                new_stuff = self.xai.read(new_addr)
            except ValueError:
                new_stuff = "\0" * 0x1000
            if new_stuff == None:
                return None
            stuff_read = stuff_read + new_stuff
            new_addr = new_addr + 0x1000

        if left_over > 0:
            try:
                new_stuff = self.xai.read(new_addr)
            except ValueError:
                new_stuff = "\0" * 0x1000
            if new_stuff == None:
                return None
            stuff_read = stuff_read + new_stuff[:left_over]
        return stuff_read

    def read(self, path, size, offset):
        if path != mem_path:
            return -errno.ENOENT
        return self.zread(offset, size)

    def main(self, *a, **kw):
        # Setup physical memory
        if hasattr(self, "domain"):
            self.xai = pyxa_instance(self.domain)
        else:
            self.parser.error("PyXaFS: must provide a Xen domain to mount")
        Fuse.main(self, *a, **kw)

def main():
    usage="""
Access the memory of a Xen guest as a regular file.

Mount options:
    domain: the domain whose memory you want to access

""" + Fuse.fusage
    fs = PyXaFS(version="%prog " + fuse.__version__,
                 usage=usage,
                 dash_s_do='setsingle')
    fs.parser.add_option(mountopt="domain", metavar="DOMAIN", type="int",
        default=0, help="the Xen domain to mount")
    fs.parse(values=fs, errex=1)
    fs.main()

if __name__ == '__main__':
    main()

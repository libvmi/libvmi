#!/usr/bin/env python3


import os
from cffi import FFI

CDEF_FILE = 'libvmi_cdef.h'


ffi = FFI()
# set source
ffi.set_source("_libvmi",
    """
    #include <libvmi/libvmi.h>
    """,
    libraries=['vmi'])

script_dir = os.path.dirname(os.path.realpath(__file__))
# we read our C definitions from an external file
# easier to maintain + C syntax highlighting
with open(os.path.join(script_dir, CDEF_FILE)) as cdef_file:
    cdef_content = cdef_file.read()
ffi.cdef(cdef_content)

if __name__ == "__main__":
    ffi.compile(verbose=True)

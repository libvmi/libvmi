#!/usr/bin/env python3


import os
from cffi import FFI

CDEF_FILES = ['libvmi_cdef.h', 'events_cdef.h']


ffi = FFI()
# set source
ffi.set_source("_libvmi",
    """
    #include <libvmi/libvmi.h>
    #include <libvmi/events.h>
    """,
    libraries=['vmi'])

script_dir = os.path.dirname(os.path.realpath(__file__))
# we read our C definitions from an external file
# easier to maintain + C syntax highlighting
ffi_cdef_content = ""
for cdef_file in CDEF_FILES:
    with open(os.path.join(script_dir, cdef_file)) as f:
        ffi_cdef_content += '\n' + f.read()

ffi.cdef(ffi_cdef_content)

if __name__ == "__main__":
    ffi.compile(verbose=True)

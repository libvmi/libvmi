"""
PyVMI is a python language wrapper for the LibVMI Library. The LibVMI Library
is an introspection library that simplifies access to memory in a target
virtual machine or in a file containing a dump of a system's physical memory.

Author: Bryan D. Payne (bdpayne@acm.org)

Copyright 2014 Bryan D. Payne

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
import functools
import os

from cffi import FFI


INTERFACE_H = os.path.dirname(os.path.abspath(__file__)) + '/interface.h'
__all__ = ["ffi", "lib"]


# Setup CFFI with LibVMI
ffi = FFI()

ffi.cdef(open(INTERFACE_H, 'r').read())
lib = ffi.verify('#include <libvmi/libvmi.h>',
                 libraries=['vmi'],
                 ext_package='pyvmi')


# Convert return values from LibVMI
#  :VMI_SUCCESS --> True
#  :VMI_FAILURE --> False
def wrap_libvmi_func(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        return (ret == lib.VMI_SUCCESS or  # cffi >= 0.6
                ret == 'VMI_SUCCESS')      # cffi <= 0.5
    return wrapper


# wrap functions that return status_t
lib.vmi_init = wrap_libvmi_func(lib.vmi_init)
lib.vmi_init_custom = wrap_libvmi_func(lib.vmi_init_custom)
lib.vmi_init_complete = wrap_libvmi_func(lib.vmi_init_complete)
lib.vmi_init_complete_custom = wrap_libvmi_func(lib.vmi_init_complete_custom)
lib.vmi_destroy = wrap_libvmi_func(lib.vmi_destroy)

lib.vmi_read_8_ksym = wrap_libvmi_func(lib.vmi_read_8_ksym)
lib.vmi_read_16_ksym = wrap_libvmi_func(lib.vmi_read_16_ksym)
lib.vmi_read_32_ksym = wrap_libvmi_func(lib.vmi_read_32_ksym)
lib.vmi_read_64_ksym = wrap_libvmi_func(lib.vmi_read_64_ksym)
lib.vmi_read_addr_ksym = wrap_libvmi_func(lib.vmi_read_addr_ksym)

lib.vmi_read_8_va = wrap_libvmi_func(lib.vmi_read_8_va)
lib.vmi_read_16_va = wrap_libvmi_func(lib.vmi_read_16_va)
lib.vmi_read_32_va = wrap_libvmi_func(lib.vmi_read_32_va)
lib.vmi_read_64_va = wrap_libvmi_func(lib.vmi_read_64_va)
lib.vmi_read_addr_va = wrap_libvmi_func(lib.vmi_read_addr_va)
lib.vmi_convert_str_encoding = wrap_libvmi_func(lib.vmi_convert_str_encoding)

lib.vmi_read_8_pa = wrap_libvmi_func(lib.vmi_read_8_pa)
lib.vmi_read_16_pa = wrap_libvmi_func(lib.vmi_read_16_pa)
lib.vmi_read_32_pa = wrap_libvmi_func(lib.vmi_read_32_pa)
lib.vmi_read_64_pa = wrap_libvmi_func(lib.vmi_read_64_pa)
lib.vmi_read_addr_pa = wrap_libvmi_func(lib.vmi_read_addr_pa)

lib.vmi_write_8_ksym = wrap_libvmi_func(lib.vmi_write_8_ksym)
lib.vmi_write_16_ksym = wrap_libvmi_func(lib.vmi_write_16_ksym)
lib.vmi_write_32_ksym = wrap_libvmi_func(lib.vmi_write_32_ksym)
lib.vmi_write_64_ksym = wrap_libvmi_func(lib.vmi_write_64_ksym)

lib.vmi_write_8_va = wrap_libvmi_func(lib.vmi_write_8_va)
lib.vmi_write_16_va = wrap_libvmi_func(lib.vmi_write_16_va)
lib.vmi_write_32_va = wrap_libvmi_func(lib.vmi_write_32_va)
lib.vmi_write_64_va = wrap_libvmi_func(lib.vmi_write_64_va)

lib.vmi_write_8_pa = wrap_libvmi_func(lib.vmi_write_8_pa)
lib.vmi_write_16_pa = wrap_libvmi_func(lib.vmi_write_16_pa)
lib.vmi_write_32_pa = wrap_libvmi_func(lib.vmi_write_32_pa)
lib.vmi_write_64_pa = wrap_libvmi_func(lib.vmi_write_64_pa)

lib.vmi_get_vcpureg = wrap_libvmi_func(lib.vmi_get_vcpureg)
lib.vmi_pause_vm = wrap_libvmi_func(lib.vmi_pause_vm)
lib.vmi_resume_vm = wrap_libvmi_func(lib.vmi_resume_vm)

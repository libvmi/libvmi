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
import struct

from .interface import ffi, lib
from .exceptions import LibvmiError


# provide quick access to libvmi constants
C = lib


class Libvmi(object):
    #
    # Init and destruct
    #
    def init(self, flags, name):
        self.vmi = ffi.new('vmi_instance_t *')
        if not lib.vmi_init(self.vmi, flags, name):
            raise LibvmiError()
        return self

    def init_custom(self, flags, config):
        pass

    def init_complete(self, config):
        pass

    def init_complete_custom(self, config):
        pass

    def destroy(self):
        pass

    #
    # Memory translation
    #
    def translate_kv2p(self, vaddr):
        return lib.vmi_translate_kv2p(self.vmi[0], vaddr)

    def translate_uv2p(self, vaddr, pid):
        return lib.vmi_translate_uv2p(self.vmi[0], vaddr, pid)

    def translate_ksym2v(self, symbol):
        return lib.vmi_translate_ksym2v(self.vmi[0], symbol)

    def pid_to_dtb(self, pid):
        return lib.vmi_pid_to_dtb(self.vmi[0], pid)

    def pagetable_lookup(self, dtb, vaddr):
        pass

    #
    # Memory read
    #
    def read_ksym(self, sym, count):
        data = ffi.new('unsigned char[%d]' % count)
        if not lib.vmi_read_ksym(self.vmi[0], sym, data, count):
            raise LibvmiError()
        return ffi.buffer(data)

    def read_va(self, vaddr, pid, count):
        data = ffi.new('unsigned char[%d]' % count)
        if not lib.vmi_read_va(self.vmi[0], vaddr, pid, data, count):
            raise LibvmiError()
        return ffi.buffer(data)

    def read_pa(self, paddr, count):
        data = ffi.new('unsigned char[%d]' % count)
        if not lib.vmi_read_pa(self.vmi[0], paddr, data, count):
            raise LibvmiError()
        return ffi.buffer(data)

    def read_8_ksym(self, sym):
        return struct.unpack('B', self.read_ksym(sym, 1))[0]

    def read_16_ksym(self, sym):
        return struct.unpack('H', self.read_ksym(sym, 2))[0]

    def read_32_ksym(self, sym):
        return struct.unpack('I', self.read_ksym(sym, 4))[0]

    def read_64_ksym(self, sym):
        return struct.unpack('Q', self.read_ksym(sym, 8))[0]

    def read_addr_ksym(self, sym):
        value = ffi.new('addr_t *')
        if not lib.vmi_read_addr_ksym(self.vmi[0], sym, value):
            raise LibvmiError()
        return value[0]

    def read_str_ksym(self, sym):
        value = lib.vmi_read_str_ksym(self.vmi[0], sym)
        if value == ffi.NULL:
            return None
        else:
            return ffi.string(value)

    def read_8_va(self, vaddr, pid):
        return struct.unpack('B', self.read_va(vaddr, pid, 1))[0]

    def read_16_va(self, vaddr, pid):
        return struct.unpack('H', self.read_va(vaddr, pid, 2))[0]

    def read_32_va(self, vaddr, pid):
        return struct.unpack('I', self.read_va(vaddr, pid, 4))[0]

    def read_64_va(self, vaddr, pid):
        return struct.unpack('Q', self.read_va(vaddr, pid, 8))[0]

    def read_addr_va(self, vaddr, pid):
        value = ffi.new('addr_t *')
        if not lib.vmi_read_addr_va(self.vmi[0], vaddr, pid, value):
            raise LibvmiError()
        return value[0]

    def read_str_va(self, vaddr, pid):
        value = lib.vmi_read_str_va(self.vmi[0], vaddr, pid)
        if value == ffi.NULL:
            return None
        else:
            return ffi.string(value)

    def read_unicode_str_va(self, vaddr, pid):
        pass

    def free_unicode_str(self, p_us):
        pass

    def read_8_pa(self, paddr):
        return struct.unpack('B', self.read_pa(paddr, 1))[0]

    def read_16_pa(self, paddr):
        return struct.unpack('H', self.read_pa(paddr, 2))[0]

    def read_32_pa(self, paddr):
        return struct.unpack('I', self.read_pa(paddr, 4))[0]

    def read_64_pa(self, paddr):
        return struct.unpack('Q', self.read_pa(paddr, 8))[0]

    def read_addr_pa(self, paddr):
        value = ffi.new('addr_t *')
        if not lib.vmi_read_addr_pa(self.vmi[0], paddr, value):
            raise LibvmiError()
        return value[0]

    def read_str_pa(self, paddr):
        value = lib.vmi_read_str_pa(self.vmi[0], paddr)
        if value == ffi.NULL:
            return None
        else:
            return ffi.string(value)

    #
    # Memory write
    #

    #
    # Others
    #
    def get_offset(self, name):
        return lib.vmi_get_offset(self.vmi[0], name)

    def get_page_mode(self):
        return lib.vmi_get_page_mode(self.vmi[0])

    def get_ostype(self):
        return lib.vmi_get_ostype(self.vmi[0])

    def get_vcpureg(self, reg, vcpu):
        value = ffi.new('reg_t *')
        if not lib.vmi_get_vcpureg(self.vmi[0], value, reg, vcpu):
            raise LibvmiError()
        return value[0]

    def get_memsize(self):
        return lib.vmi_get_memsize(self.vmi[0])

    # get name
    # get vmid
    # get access mode
    # get winver str
    # print hex
    # print hex pa
    # print hex va
    # print hex ksym
    # pause vm
    # resume vm
    # v2pcache flush
    # v2pcache add
    # symcache flush
    # symcache add
    # pidcache flush
    # pidcache add

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
from .libvmi import Libvmi, C


class Pyvmi(object):
    offset_names = {
        'Linux': {
            'tasks_offset': 'linux_tasks',
            'mm_offset': 'linux_mm',
            'pid_offset': 'linux_pid',
            'name_offset': 'linux_name',
            'pgd_offset': 'linux_pgd',
        },
        'Windows': {
            'tasks_offset': 'win_tasks',
            'pdbase_offset': 'win_pdbase',
            'pid_offset': 'win_pid',
            'name_offset': 'win_pname',
        },
    }

    def __init__(self, name):
        self.vmi = Libvmi().init(C.VMI_AUTO | C.VMI_INIT_COMPLETE, name)

    def __del__(self):
        self.vmi.destroy()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.vmi.destroy()

    def __str__(self):
        pass

    def _get_offset_ref(self, os, key):
        try:
            return self.offset_names[os][key]
        except KeyError:
            return None

    def __getitem__(self, key):
        # Set the os type value
        os = self.vmi.get_ostype()
        if (os == C.VMI_OS_LINUX or os == 'VMI_OS_LINUX'):
            os = 'Linux'
        elif (os == C.VMI_OS_WINDOWS or os == 'VMI_OS_WINDOWS'):
            os = 'Windows'
        else:
            os = 'Unknown'

        # Return os type, if requested
        if key == 'ostype':
            return os

        # Return offset, if requested
        offset_ref = self._get_offset_ref(os, key)
        if offset_ref:
            return self.vmi.get_offset(offset_ref)

        raise KeyError

    def _addrlen(self):
        """return 4 for 32-bit systems, 8 for 64-bit systems"""
        mode = self.vmi.get_page_mode()
        if (mode == C.VMI_PM_IA32E or mode == 'VMI_PM_IA32E'):
            return 8
        else:
            return 4

    def translate(self, ksym=None, va=None, pid=0):
        if ksym:
            return self.vmi.translate_ksym2v(ksym)
        elif va:
            return self.vmi.translate_uv2p(va, pid)

    def read(self, pa=None, va=None, ksym=None,
             pid=0, size=None, string=False):
        if not size:
            size = self._addrlen()

        if pa:
            if string:
                buf = self.vmi.read_str_pa(pa)
            else:
                buf = self.vmi.read_pa(pa, size)
        elif va:
            if string:
                buf = self.vmi.read_str_va(va, pid)
            else:
                buf = self.vmi.read_va(va, pid, size)
        elif ksym:
            if string:
                buf = self.vmi.read_str_ksym(ksym)
            else:
                buf = self.vmi.read_ksym(ksym, size)

        if string:
            return buf
        elif size == 1:
            return struct.unpack('B', buf)[0]
        elif size == 2:
            return struct.unpack('H', buf)[0]
        elif size == 4:
            return struct.unpack('I', buf)[0]
        elif size == 8:
            return struct.unpack('Q', buf)[0]
        else:
            return struct.unpack('s#', buf)[0]

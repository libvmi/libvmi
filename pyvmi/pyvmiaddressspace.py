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
import volatility.addrspace as addrspace
import urllib
from pyvmi.libvmi import Libvmi, C


class PyVmiAddressSpace(addrspace.BaseAddressSpace):
    """
    This address space can be used in conjunction with LibVMI
    and the Python bindings for LibVMI.  The end result is that
    you can connect Volatility to view the memory of a running
    virtual machine from any virtualization platform that
    LibVMI supports.

    For this AS to be instantiated, we need the VM name to
    connect to.
    """

    order = 90

    def __init__(self, base, config, layered=False, **kwargs):
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)
        self.as_assert(base is None or layered, 'Must be first Address Space')
        self.as_assert(config.LOCATION.startswith('vmi://'),
                       "Location doesn't start with vmi://")
        self.config = dict(inittype="partial")
        if config.LOCATION.find('domid/') == 6:
            self.domid = int(urllib.url2pathname(config.LOCATION[12:]))
            self.config['domid'] = self.domid
        elif config.LOCATION.find('name/') == 6:
            self.name = urllib.url2pathname(config.LOCATION[11:])
            self.config['name'] = self.name
        else:
            self.name = urllib.url2pathname(config.LOCATION[6:])
            self.config['name'] = self.name

        self.vmi = Libvmi().init(C.VMI_AUTO | C.VMI_INIT_PARTIAL,
                                 self.config['name'])
        self.as_assert(self.vmi is not None, 'VM not found')
        self.dtb = self.get_cr3()

    def __read_bytes(self, addr, length, pad):
        if addr > self.vmi.get_memsize():
            return ''

        # This should not happen but in case it does
        # pad the end of the read
        end = addr + length
        if end > self.vmi.get_memsize():
            pad = True

        try:
            memory = self.vmi.read_pa(addr, length)
            if pad:
                memory = bytes(memory).ljust(length, '\0')
            else:
                memory = bytes(memory)
        except:
            memory = '\0' * length

        return memory

    def read(self, addr, length):
        return self.__read_bytes(addr, length, pad=False)

    def zread(self, addr, length):
        return self.__read_bytes(addr, length, pad=True)

    def is_valid_address(self, addr):
        if addr is None:
            return False
        return 4096 < addr < self.vmi.get_memsize() - 1

    def write(self, addr, data):
        return False

    def get_cr3(self):
        cr3 = self.vmi.get_vcpureg(C.CR3, 0)
        return cr3

    def get_available_addresses(self):
        yield (4096, self.vmi.get_memsize() - 4096)
        return

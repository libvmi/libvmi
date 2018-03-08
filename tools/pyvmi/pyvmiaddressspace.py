# Volatility
#
# Copyright 2011 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
# retains certain rights in this software.
#
# Authors:
# bdpayne@acm.org (Bryan D. Payne)
# muscat_mat@hotmail.com (Matthew Muscat)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import volatility.addrspace as addrspace
import urllib
import pyvmi

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
    vmi = None

    def __init__(self, base, config, layered=False, **kwargs):
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)
	self.as_assert(base == None or layered, "Must be first Address Space")
        self.as_assert(
                config.LOCATION.startswith("vmi://"),
                "Location doesn't start with vmi://")
        self.config = dict(inittype="partial")
        if config.LOCATION.find("domid/") == 6:
            self.domid = int(urllib.url2pathname(config.LOCATION[12:]))
            self.config['domid']=self.domid
        elif config.LOCATION.find("name/") == 6:
            self.name = urllib.url2pathname(config.LOCATION[11:])
            self.config['name'] = self.name
        else:
            self.name = urllib.url2pathname(config.LOCATION[6:])
            self.config['name'] = self.name
	if PyVmiAddressSpace.vmi is None:
		PyVmiAddressSpace.vmi = pyvmi.init(self.config)
        self.as_assert(not PyVmiAddressSpace.vmi is None, "VM not found")
        self.dtb = self.get_cr3()

    def __read_bytes(self, addr, length, pad):
        if addr > PyVmiAddressSpace.vmi.get_memsize():
            return ''

        # This should not happen but in case it does
        # pad the end of the read
        end = addr + length
        if end > PyVmiAddressSpace.vmi.get_memsize():
            pad = True

        try:
	    if pad:
                memory = PyVmiAddressSpace.vmi.zread_pa(addr, length)
            else:
                memory = PyVmiAddressSpace.vmi.read_pa(addr, length)
        except:
            memory = ''

        return memory

    def read(self, addr, length):
        return self.__read_bytes(addr, length, pad=False)

    def zread(self, addr, length):
        return self.__read_bytes(addr, length, pad=True)

    def is_valid_address(self, addr):
        if addr == None:
            return False
	
        return 4096 < addr < PyVmiAddressSpace.vmi.get_memsize() - 1

    def write(self, addr, data):
        nbytes = PyVmiAddressSpace.vmi.write_pa(addr, data)
        if nbytes != len(data):
            return False

        return True

    def get_cr3(self):
        return PyVmiAddressSpace.vmi.get_vcpureg("cr3", 0)

    def get_available_addresses(self):
        yield (0, PyVmiAddressSpace.vmi.get_memsize())
        return

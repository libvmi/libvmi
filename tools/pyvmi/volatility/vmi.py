# Volatility
#
# Copyright 2011 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
# retains certain rights in this software.
#
# Authors:
# bdpayne@acm.org (Bryan D. Payne)
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
libvmi = None
try:
    import libvmi
    from libvmi import Libvmi, CR3
except ImportError:
    pass
import volatility.addrspace as addrspace


class VMIAddressSpace(addrspace.BaseAddressSpace):
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
        self.as_assert(libvmi, "The LibVMI python bindings must be installed")
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)
        self.as_assert(base == None or layered, 'Must be first Address Space')
        self.as_assert(config.LOCATION.startswith("vmi://"),
                       "Location doesn't start with vmi://")

        domain = config.LOCATION[len("vmi://"):]
        self.vmi = Libvmi(domain, partial=True)
        self.dtb = self.vmi.get_vcpu_reg(CR3, 0)

    def close(self):
        self.vmi.destroy()

    def read(self, addr, length):
        buffer, bytes_read = self.vmi.read_pa(addr, length)
        if bytes_read != length:
            raise RuntimeError('Error while reading physical memory at '
                               '{}'.format(hex(addr)))
        return buffer

    def zread(self, addr, length):
        buffer, bytes_read = self.vmi.read_pa(addr, length)
        if bytes_read != length:
            # fill with zeroes
            buffer += bytes(length - bytes_read).decode()
        return buffer

    def write(self, addr, data):
        bytes_written = self.vmi.write_pa(addr, data)
        if bytes_written != len(data):
            return False
        return True

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return 4096 < addr < self.vmi.get_memsize() - 1

    def get_available_addresses(self):
        yield (0, self.vmi.get_memsize())

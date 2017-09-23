#!/usr/bin/env python3

"""module-list.py.

Usage:
  module-list.py [options] <vm_name>

Options:
  -h --help     Show this screen.
"""

import logging
import sys
from docopt import docopt
from contextlib import contextmanager

from utils import init_logger, pause
from libvmi import Libvmi, VMIOS, PageMode



def main(args):
    if len(args) != 2:
        print('./module-list.py <vm_name>')
        return 1

    vm_name = args[1]

    with Libvmi(vm_name) as vmi:
        # pause vm for consistent memory access
        with pause(vmi):
            next_module = None
            # get ostype
            os = vmi.get_ostype()
            if os == VMIOS.LINUX:
                next_module = vmi.read_addr_ksym("modules")
            elif os == VMIOS.WINDOWS:
                next_module = vmi.read_addr_ksym("PsLoadedModuleList")
            else:
                logging.info("Unknown OS")

            list_head = next_module

            # walk the module list
            while True:
                # follow the next pointer
                tmp_next = vmi.read_addr_va(next_module, 0)

                # if we are back at the list head, we are done
                if list_head == tmp_next:
                    break

                modname = None
                # print out the module name
                if os == VMIOS.LINUX:
                    if page_mode == PageMode.IA32E:
                        modname = vmi.read_str_va(next_module + 16, 0)
                    else:
                        modname = vmi.read_str_va(next_module + 8, 0)


                elif os == VMIOS.WINDOWS:
                    page_mode = vmi.get_page_mode(0)
                    if page_mode == PageMode.IA32E:
                        modname = vmi.read_unicode_str_va(next_module + 0x58, 0)
                    else:
                        modname = vmi.read_unicode_str_va(next_module + 0x2c, 0)

                else:
                    logging.info("Unkown OS")

                if modname is not None:
                    logging.info(modname)

                next_module = tmp_next

if __name__ == '__main__':
    init_logger()
    ret = main(sys.argv)
    sys.exit(ret)

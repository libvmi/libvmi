#!/usr/bin/env python3


import logging
import sys

from utils import init_logger, pause
from libvmi import Libvmi, VMIOS


def main(args):
    if len(args) != 2:
        print('./process-list.py <vm_name>')
        return 1

    vm_name = args[1]

    with Libvmi(vm_name) as vmi:
        # get ostype
        os = vmi.get_ostype()
        # init offsets values
        tasks_offset = None
        name_offset = None
        pid_offset = None
        if os == VMIOS.LINUX:
            tasks_offset = vmi.get_offset("linux_tasks")
            name_offset = vmi.get_offset("linux_name")
            pid_offset = vmi.get_offset("linux_pid")
        elif os == VMIOS.WINDOWS:
            tasks_offset = vmi.get_offset("win_tasks")
            name_offset = vmi.get_offset("win_pname")
            pid_offset = vmi.get_offset("win_pid")
        else:
            logging.info("Unknown OS")
            return 1

        # pause vm
        with pause(vmi):
            # demonstrate name and id accessors
            name = vmi.get_name()
            id = vmi.get_vmid()

            logging.info("Process listing for VM %s (id: %s)", name, id)
            if os == VMIOS.LINUX:
                list_head = vmi.translate_ksym2v("init_task")
                list_head += tasks_offset
            elif os == VMIOS.WINDOWS:
                list_head = vmi.read_addr_ksym("PsActiveProcessHead")
            else:
                return 1
            cur_list_entry = list_head
            next_list_entry = vmi.read_addr_va(cur_list_entry, 0)

            while True:
                current_process = cur_list_entry - tasks_offset
                pid = vmi.read_32_va(current_process + pid_offset, 0)
                procname = vmi.read_str_va(current_process + name_offset, 0)

                logging.info("[%s] %s (struct addr:%s)", pid, procname, hex(current_process))
                cur_list_entry = next_list_entry
                next_list_entry = vmi.read_addr_va(cur_list_entry, 0)

                if os == VMIOS.WINDOWS and next_list_entry == list_head:
                    break
                elif os == VMIOS.LINUX and cur_list_entry == list_head:
                    break

if __name__ == '__main__':
    init_logger()
    ret = main(sys.argv)
    sys.exit(ret)

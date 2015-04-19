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
import pytest

from pyvmi.libvmi import Libvmi, C


#
# Fixtures
#
@pytest.fixture
def vmi():
    return Libvmi().init(C.VMI_AUTO | C.VMI_INIT_COMPLETE, 'winxpsp2')


#
# Init and destruct
#
def test_init():
    Libvmi().init(C.VMI_AUTO | C.VMI_INIT_PARTIAL, 'winxpsp2')


def test_init_custom():
    Libvmi().init_custom(C.VMI_AUTO | C.VMI_INIT_PARTIAL, '')


def test_init_complete():
    Libvmi().init_complete('')


def test_init_complete_custom():
    Libvmi().init_complete_custom('')


def test_destroy(vmi):
    vmi.destroy()


#
# Memory translation
#
def test_translate_kv2p(vmi):
    va = vmi.translate_ksym2v('PsInitialSystemProcess')
    pa = vmi.translate_kv2p(va)
    assert(pa != 0)


def test_translate_uv2p(vmi):
    # TODO figure out how to test this
    pass


def test_translate_ksym2v(vmi):
    va = vmi.translate_ksym2v('PsInitialSystemProcess')
    assert(va != 0)


def test_pid_to_dtb(vmi):
    failed = True
    tasks_offset = vmi.get_offset('win_tasks')
    pid_offset = vmi.get_offset('win_pid')

    list_head = vmi.read_addr_ksym('PsInitialSystemProcess')
    next_process = vmi.read_addr_va(list_head + tasks_offset, 0)

    list_head = next_process
    while (1):
        tmp_next = vmi.read_addr_va(next_process, 0)
        if list_head == tmp_next:
            break
        pid = vmi.read_32_va(next_process + pid_offset - tasks_offset, 0)
        if pid > 0:
            dtb = vmi.pid_to_dtb(pid)
            if dtb != 0:
                failed = False
                break
        next_process = tmp_next
    assert(not failed)


def test_pagetable_lookup(vmi):
    # TODO figure out how to test this
    pass


#
# Memory read
#
def test_read_ksym(vmi):
    count = 100
    read = vmi.read_ksym('PsInitialSystemProcess', count)
    assert(len(read) == count)


def test_read_va(vmi):
    count = 100
    va = vmi.translate_ksym2v('PsInitialSystemProcess')
    read = vmi.read_va(va, 0, count)
    assert(len(read) == count)


def test_read_pa(vmi):
    count = 100
    va = vmi.translate_ksym2v('PsInitialSystemProcess')
    pa = vmi.translate_kv2p(va)
    read = vmi.read_pa(pa, count)
    assert(len(read) == count)


#
# Others
#
def test_get_offset(vmi):
    tasks_offset = vmi.get_offset('win_tasks')
    assert(tasks_offset == 0x88)


def test_get_page_mode(vmi):
    mode = vmi.get_page_mode()
    assert(mode == C.VMI_PM_PAE)


def test_get_ostype(vmi):
    ostype = vmi.get_ostype()
    assert(ostype == C.VMI_OS_WINDOWS)

from builtins import object, super
from enum import Enum

from _libvmi import ffi, lib


class EventType(Enum):
    INVALID = lib.VMI_EVENT_INVALID
    MEMORY  = lib.VMI_EVENT_MEMORY
    REGISTER = lib.VMI_EVENT_REGISTER
    SINGLESTEP = lib.VMI_EVENT_SINGLESTEP
    INTERRUPT = lib.VMI_EVENT_INTERRUPT
    GUEST_REQUEST = lib.VMI_EVENT_GUEST_REQUEST
    CPUID = lib.VMI_EVENT_CPUID
    DEBUG_EXCEPTION = lib.VMI_EVENT_DEBUG_EXCEPTION
    PRIVILEGED_CALL = lib.VMI_EVENT_PRIVILEGED_CALL
    DESCRIPTOR_ACCESS = lib.VMI_EVENT_DESCRIPTOR_ACCESS

EVENTS_VERSION = lib.VMI_EVENTS_VERSION


class MemAccess(Enum):
    INVALID = lib.VMI_MEMACCESS_INVALID
    N = lib.VMI_MEMACCESS_N
    R = lib.VMI_MEMACCESS_R
    W = lib.VMI_MEMACCESS_W
    X = lib.VMI_MEMACCESS_X
    RW = lib.VMI_MEMACCESS_RW
    RX = lib.VMI_MEMACCESS_RX
    WX = lib.VMI_MEMACCESS_WX
    RWX = lib.VMI_MEMACCESS_RWX
    W2X = lib.VMI_MEMACCESS_W2X
    RWX2N = lib.VMI_MEMACCESS_RWX2N


@ffi.def_extern()
def generic_event_callback(cffi_vmi, cffi_event):
    # get generic event data dict
    generic_data = ffi.from_handle(cffi_event.data)
    # get true callback
    event = generic_data['event']
    vmi = generic_data['vmi']
    callback = event.get_callback()
    # call callback with the right Python objects as args
    event_response = callback(vmi, event)
    if not event_response:
        return 0
    return event_response


class Event(object):

    def __init__(self, callback, slat_id=0, data=None):
        self.version = EVENTS_VERSION
        self.slat_id = slat_id
        self.data = data
        self.py_callback = callback
        self.generic_data = {
            'vmi': None,
            'event': self,
        }
        self.cffi_event = ffi.new("vmi_event_t *")

    def set_vmi_instance(self, vmi_instance):
        self.generic_data['vmi'] = vmi_instance

    def get_callback(self):
        return self.py_callback

    def to_cffi(self):
        self.cffi_event.version = self.version
        self.cffi_event.type = self.type.value
        self.cffi_event.slat_id = self.slat_id
        # convert our generic_data dict to a CFFI void* handle
        # and keep a reference to the handle in self.generic_handle
        self.generic_handle = ffi.new_handle(self.generic_data)
        # assign the handle to the event data
        self.cffi_event.data = self.generic_handle
        self.cffi_event.callback = lib.generic_event_callback

    def to_dict(self):
        return {
            'version': self.version,
            'type': self.type.name,
            'slat_id': self.slat_id,
            'data': self.data,
            'vcpu_id': self.cffi_event.vcpu_id,
            'x86_regs': {
                'rax': hex(self.cffi_event.x86_regs.rax),
                'rsp': hex(self.cffi_event.x86_regs.rsp),
                'rip': hex(self.cffi_event.x86_regs.rip),
            }
        }


class MemEvent(Event):

    def __init__(self, in_access, callback, gfn=None, generic=None, slat_id=0, data=None):
        super().__init__(callback, slat_id, data)
        self.type = EventType.MEMORY
        self.in_access = in_access
        self.generic = generic
        self.gfn = gfn
        if self.generic:
            self.gfn = 0

    def to_cffi(self):
        super().to_cffi()
        self.cffi_event.mem_event.in_access = self.in_access.value
        self.cffi_event.mem_event.generic = self.generic
        self.cffi_event.mem_event.gfn = self.gfn
        return self.cffi_event


class SingleStepEvent(Event):

    def __init__(self, vcpus, callback, enable=True, slat_id=0, data=None):
        super().__init__(callback, slat_id, data)
        self.type = EventType.SINGLESTEP
        self.vcpus = 0
        for vcpu in vcpus:
            mask = 1 << vcpu
            self.vcpus |= mask
        self.enable = enable

    def to_cffi(self):
        super().to_cffi()
        self.cffi_event.ss_event.vcpus = self.vcpus
        self.cffi_event.ss_event.enable = int(self.enable)
        return self.cffi_event

    def to_dict(self):
        return super().to_dict()
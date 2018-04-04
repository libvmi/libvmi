import six
from builtins import bytes
from builtins import object
from enum import Enum

from _libvmi import ffi, lib
from _glib import lib as glib


# export libvmi defines
INIT_DOMAINNAME = lib.VMI_INIT_DOMAINNAME
INIT_DOMAINID = lib.VMI_INIT_DOMAINID
INIT_EVENTS = lib.VMI_INIT_EVENTS
INIT_SHM = lib.VMI_INIT_SHM
CR3 = lib.CR3


class LibvmiError(Exception):
    pass

class VMIMode(Enum):
    XEN = 0
    KVM = 1
    FILE = 2

class VMIConfig(Enum):
    GLOBAL_FILE_ENTRY = 0
    STRING = 1
    DICT = 2


class VMIStatus(Enum):
    SUCCESS = 0
    FAILURE = 1


class LibvmiInitError(Enum):
    NONE = 0                 # No error
    DRIVER_NOT_DETECTED = 1  # Failed to auto-detect hypervisor
    DRIVER = 2               # Failed to initialize hypervisor-driver
    VM_NOT_FOUND = 3         # Failed to find the specified VM
    PAGING = 4               # Failed to determine or initialize paging functions
    OS = 5                   # Failed to determine or initialize OS functions
    EVENTS = 6               # Failed to initialize events
    SHM = 7                  # Failed to initialize SHM
    NO_CONFIG = 8            # No configuration was found for OS initialization
    NO_CONFIG_ENTRY = 9      # Configuration contained no valid entry for VM


class PageMode(Enum):
    UNKNOWN = 0             # page mode unknown
    LEGACY = 1              # x86 32-bit paging
    PAE = 2                 # x86 PAE paging
    IA32E = 3               # x86 IA-32e paging
    AARCH32 = 4             # ARM 32-bit paging
    AARCH64 = 5             # ARM 64-bit paging


class VMIArch(Enum):
    VMI_ARCH_UNKNOWN = 0    # Unknown architecture
    VMI_ARCH_X86 = 1        # x86 32-bit architecture
    VMI_ARCH_X86_64 = 2     # x86 64-bit architecture
    VMI_ARCH_ARM32 = 3      # ARM 32-bit architecture
    VMI_ARCH_ARM64 = 4      # ARM 64-bit architecture

class VMIOS(Enum):
    UNKNOWN = 0
    LINUX = 1
    WINDOWS = 2

class VMIWinVer(Enum):
    OS_WINDOWS_NONE     = 0         # TODO 0 ? Not Windows
    OS_WINDOWS_UNKNOWN  = 1         # TODO 1 ? Is Windows, not sure which
    OS_WINDOWS_2000     = 0x0208    # Magic value for Windows 2000
    OS_WINDOWS_XP       = 0x0290    # Magic value for Windows XP
    OS_WINDOWS_2003     = 0x0318    # Magic value for Windows 2003
    OS_WINDOWS_VISTA    = 0x0328    # Magic value for Windows Vista
    OS_WINDOWS_2008     = 0x0330    # Magic value for Windows 2008
    OS_WINDOWS_7        = 0x0340    # Magic value for Windows 7
    OS_WINDOWS_8        = 0x0360    # Magic value for Windows 8
    OS_WINDOWS_10       = 0x0361    # TODO last + 1 ?

class TranslateMechanism(Enum):
    NONE            = 1
    PROCESS_DTB     = 2
    PROCESS_PID     = 3
    KERNEL_SYMBOL   = 4

class AccessContext(object):

    def __init__(self, tr_mechanism=TranslateMechanism.NONE, addr=0,
                 ksym=None, dtb=0, pid=0):
        if not isinstance(tr_mechanism, TranslateMechanism):
            raise RuntimeError('must specify a valid TranslateMechanism')

        self.tr_mechanism = tr_mechanism
        if self.tr_mechanism == TranslateMechanism.KERNEL_SYMBOL:
            if not isinstance(ksym, six.string_types):
                raise RuntimeError("ksym must be a string")
            self.ksym = ksym
        self.addr = addr
        self.dtb = dtb
        self.pid = pid

    def to_ffi(self):
        ffi_ctx = ffi.new("access_context_t *")
        ffi_ctx.translate_mechanism = self.tr_mechanism.value
        if self.tr_mechanism == TranslateMechanism.KERNEL_SYMBOL:
            ffi_ctx.ksym = ffi.new("char []", self.ksym.encode())
        else:
            ffi_ctx.addr = self.addr
            ffi_ctx.dtb = self.dtb
            ffi_ctx.pid = self.pid
        return ffi_ctx

def check(status, error='VMI_FAILURE'):
    if VMIStatus(status) != VMIStatus.SUCCESS:
        raise LibvmiError(error)

class Libvmi(object):

    __slots__ = (
        'opaque_vmi',
        'vmi',
    )

    def __init__(self, domain, init_flags=INIT_DOMAINNAME, init_data=ffi.NULL,
                 config_mode=VMIConfig.GLOBAL_FILE_ENTRY, config=ffi.NULL,
                 mode=None, partial=False):
        self.vmi = ffi.NULL
        self.opaque_vmi = ffi.new("vmi_instance_t *")
        init_error = ffi.new("vmi_init_error_t *")
        # avoid GC to free ghashtable inserted values
        ghash_ref = dict()
        ghash = None
        if partial:
            # vmi_init
            if not mode:
                # calling vmi_get_access_mode to auto determine vmi_mode
                mode = self.get_access_mode(domain, init_flags, init_data)
            if not isinstance(mode, VMIMode):
                raise RuntimeError("mode is not an instance of VMIMode")
            if not init_flags & INIT_DOMAINNAME and not init_flags & INIT_DOMAINID:
                raise RuntimeError("Partial init, init_flags must be either INIT_DOMAINAME or INIT_DOMAINID")
            domain = domain.encode()

            status = lib.vmi_init(self.opaque_vmi,
                                  mode.value,
                                  domain,
                                  init_flags,
                                  init_data,
                                  init_error)
        else:
            # vmi_init_complete
            # if INIT_DOMAINNAME, we need to encode the string from str to bytes
            if init_flags & INIT_DOMAINNAME or init_flags & INIT_DOMAINID:
                domain = domain.encode()
            # same for VMI_CONFIG_STRING
            if config_mode == VMIConfig.STRING:
                config = config.encode()
            elif config_mode == VMIConfig.DICT:
                # need to convert config to a GHashTable
                g_str_hash_addr = ffi.addressof(glib, "g_str_hash")
                g_str_equal_addr = ffi.addressof(glib, "g_str_equal")
                ghash = glib.g_hash_table_new(g_str_hash_addr, g_str_equal_addr)

                for k, v in list(config.items()):
                    key = k.encode()
                    if isinstance(v, str):
                        value = v.encode()
                    elif isinstance(v, int):
                        value = ffi.new("int*", v)
                    else:
                        raise RuntimeError("Invalid value {} in config hash".format(v))
                    glib.g_hash_table_insert(ghash, key, value)
                    # keep a reference to avoid GC
                    ghash_ref[key] = value

                config = ghash

            # init libvmi
            status = lib.vmi_init_complete(self.opaque_vmi,
                                           domain,
                                           init_flags,
                                           init_data,
                                           config_mode.value,
                                           config,
                                           init_error)
        error_msg = LibvmiInitError(init_error[0]).name
        check(status, error_msg)
        # store handle to real vmi_instance_t
        self.vmi = self.opaque_vmi[0]
        # destroy ghashtable if necessary
        if ghash is not None:
            glib.g_hash_table_destroy(ghash)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.destroy()

    def init_paging(self, flags):
        page_mode = lib.vmi_init_paging(self.vmi, flags)
        return PageMode(page_mode)

    def init_os(self, config_mode=VMIConfig.GLOBAL_FILE_ENTRY, config=ffi.NULL):
        init_error = ffi.new("vmi_init_error_t *")
        ghash_ref = dict()
        if config_mode == VMIConfig.STRING:
            config = config.encode()
        elif config_mode == VMIConfig.DICT:
            ghash = None
            # need to convert config to a GHashTable
            g_str_hash_addr = ffi.addressof(glib, "g_str_hash")
            g_str_equal_addr = ffi.addressof(glib, "g_str_equal")
            ghash = glib.g_hash_table_new(g_str_hash_addr, g_str_equal_addr)

            for k, v in list(config.items()):
                key = k.encode()
                if isinstance(v, str):
                    value = v.encode()
                elif isinstance(v, int):
                    value = ffi.new("int*", v)
                else:
                    raise RuntimeError("Invalid value {} in config hash".format(v))
                glib.g_hash_table_insert(ghash, key, value)
                # keep a reference to avoid GC
                ghash_ref[key] = value

            config = ghash
        os = lib.vmi_init_os(self.vmi, config_mode.value, config, init_error)
        return (VMIOS(os), init_error[0])

    def destroy(self):
        if self.vmi:
            status = lib.vmi_destroy(self.vmi)
            check(status)
        self.opaque_vmi = None
        self.vmi = None

    def get_library_arch(self):
        arch = lib.vmi_get_library_arch()
        return VMIArch(arch)

    def get_rekall_path(self):
        value = lib.vmi_get_rekall_path(self.vmi)
        if value == ffi.NULL:
            return None
        return ffi.string(value).decode()

    # memory translations
    def translate_kv2p(self, vaddr):
        paddr = ffi.new("addr_t *")
        status = lib.vmi_translate_kv2p(self.vmi, vaddr, paddr)
        check(status)
        return paddr[0]

    def translate_uv2p(self, vaddr, pid):
        paddr = ffi.new("addr_t *")
        status = lib.vmi_translate_uv2p(self.vmi, vaddr, pid, paddr)
        check(status)
        return paddr[0]

    def translate_ksym2v(self, symbol):
        vaddr = ffi.new("addr_t *")
        status = lib.vmi_translate_ksym2v(self.vmi, symbol.encode(), vaddr)
        check(status)
        return vaddr[0]

    def translate_sym2v(self, ctx, symbol):
        vaddr = ffi.new("addr_t *")
        status = lib.vmi_translate_sym2v(self.vmi, ctx.to_ffi(), symbol.encode(), vaddr)
        check(status)
        return vaddr[0]

    def translate_v2sym(self, ctx, addr):
        symbol = lib.vmi_translate_v2sym(self.vmi, ctx.to_ffi(), addr)
        if symbol == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(symbol).decode()

    def translate_v2ksym(self, ctx, addr):
        symbol = lib.vmi_translate_v2ksym(self.vmi, ctx.to_ffi(), addr)
        if symbol == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(symbol).decode()

    def pid_to_dtb(self, pid):
        dtb = ffi.new('addr_t *')
        status = lib.vmi_pid_to_dtb(self.vmi, pid, dtb)
        check(status)
        return dtb[0]

    def dtb_to_pid(self, dtb):
        pid = ffi.new("vmi_pid_t *")
        status = lib.vmi_dtb_to_pid(self.vmi, dtb, pid)
        check(status)
        return pid[0]

    def pagetable_lookup(self, dtb, vaddr):
        paddr = ffi.new("addr_t *")
        status = lib.vmi_pagetable_lookup(self.vmi, dtb, vaddr, paddr)
        check(status)
        return paddr[0]

    def pagetable_lookup_extended(self, dtb, vaddr):
        page_info = ffi.new("page_info_t *")
        status = lib.vmi_pagetable_lookup_extended(self.vmi, dtb, vaddr, page_info)
        check(status)
        return page_info

    # read
    def read(self, ctx, count):
        buffer = ffi.new("char[]", count)
        bytes_read = ffi.new("size_t *")
        status = lib.vmi_read(self.vmi, ctx.to_ffi(), count, buffer, bytes_read)
        check(status)
        # transform into Python bytes
        buffer = ffi.unpack(buffer, bytes_read[0])
        return (buffer, bytes_read[0])

    def read_8(self, ctx):
        value = ffi.new("uint8_t *")
        status = lib.vmi_read_8(self.vmi, ctx.to_ffi(), value)
        check(status)
        return value[0]

    def read_16(self, ctx):
        value = ffi.new("uint16_t *")
        status = lib.vmi_read_16(self.vmi, ctx.to_ffi(), value)
        check(status)
        return value[0]

    def read_32(self, ctx):
        value = ffi.new("uint32_t *")
        status = lib.vmi_read_32(self.vmi, ctx.to_ffi(), value)
        check(status)
        return value[0]

    def read_64(self, ctx):
        value = ffi.new("uint64_t *")
        status = lib.vmi_read_64(self.vmi, ctx.to_ffi(), value)
        check(status)
        return value[0]

    def read_addr(self, ctx):
        value = ffi.new("addr_t *")
        status = lib.vmi_read_addr(self.vmi, ctx.to_ffi(), value)
        check(status)
        return value[0]

    def read_str(self, ctx):
        value = lib.vmi_read_str_va(self.vmi, ctx.to_ffi())
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(value).decode()

    def read_unicode_str(self, ctx):
        value = lib.vmi_read_unicode_str(self.vmi, ctx.to_ffi())
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        encoding = ffi.string(value.encoding).decode()
        buffer = ffi.string(value.contents, value.length)
        self.free_unicode_str(value)
        return buffer.decode(encoding)

    def read_ksym(self, symbol, count):
        buffer = ffi.new("char[]", count)
        bytes_read = ffi.new("size_t *")
        status = lib.vmi_read_ksym(self.vmi, symbol.encode(), count, buffer, bytes_read)
        check(status)
        # transform into Python bytes
        buffer = ffi.string(buffer, bytes_read[0])
        return (buffer, bytes_read[0])

    def read_va(self, vaddr, pid, count):
        buffer = ffi.new("char[]", count)
        bytes_read = ffi.new("size_t *")
        status = lib.vmi_read_va(self.vmi, vaddr, pid, count, buffer, bytes_read)
        check(status)
        # transform into Python bytes
        buffer = ffi.unpack(buffer, bytes_read[0])
        return (buffer, bytes_read[0])

    def read_pa(self, paddr, count, padding=False):
        buffer = ffi.new("char[]", count)
        bytes_read = ffi.new("size_t *")
        status = lib.vmi_read_pa(self.vmi, paddr, count, buffer, bytes_read)
        # transform into Python bytes
        buffer = ffi.unpack(buffer, bytes_read[0])
        if padding:
            if VMIStatus(status) == VMIStatus.FAILURE:
                # pad with zeroes
                pad_size = count - bytes_read[0]
                buffer += bytes(pad_size)
        else:
            check(status)
        return (buffer, bytes_read[0])

    def read_8_ksym(self, symbol):
        value = ffi.new("uint8_t *")
        status = lib.vmi_read_8_ksym(self.vmi, symbol.encode(), value)
        check(status)
        return value[0]

    def read_16_ksym(self, symbol):
        value = ffi.new("uint16_t *")
        status = lib.vmi_read_16_ksym(self.vmi, symbol.encode(), value)
        check(status)
        return value[0]

    def read_32_ksym(self, symbol):
        value = ffi.new("uint32_t *")
        status = lib.vmi_read_32_ksym(self.vmi, symbol.encode(), value)
        check(status)
        return value[0]

    def read_64_ksym(self, symbol):
        value = ffi.new("uint64_t *")
        status = lib.vmi_read_64_ksym(self.vmi, symbol.encode(), value)
        check(status)
        return value[0]

    def read_addr_ksym(self, symbol):
        value = ffi.new("addr_t *")
        status = lib.vmi_read_addr_ksym(self.vmi, symbol.encode(), value)
        check(status)
        return value[0]

    def read_8_va(self, vaddr, pid):
        value = ffi.new("uint8_t *")
        status = lib.vmi_read_8_va(self.vmi, vaddr, pid, value)
        check(status)
        return value[0]

    def read_16_va(self, vaddr, pid):
        value = ffi.new("uint16_t *")
        status = lib.vmi_read_16_va(self.vmi, vaddr, pid, value)
        check(status)
        return value[0]

    def read_32_va(self, vaddr, pid):
        value = ffi.new("uint32_t *")
        status = lib.vmi_read_32_va(self.vmi, vaddr, pid, value)
        check(status)
        return value[0]

    def read_64_va(self, vaddr, pid):
        value = ffi.new("uint64_t *")
        status = lib.vmi_read_64_va(self.vmi, vaddr, pid, value)
        check(status)
        return value[0]

    def read_addr_va(self, vaddr, pid):
        value = ffi.new("addr_t *")
        status = lib.vmi_read_addr_va(self.vmi, vaddr, pid, value)
        check(status)
        return value[0]

    def read_str_va(self, vaddr, pid):
        value = lib.vmi_read_str_va(self.vmi, vaddr, pid)
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(value).decode()

    def read_unicode_str_va(self, vaddr, pid):
        value = lib.vmi_read_unicode_str_va(self.vmi, vaddr, pid)
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        encoding = ffi.string(value.encoding).decode()
        buffer = ffi.string(value.contents, value.length)
        self.free_unicode_str(value)
        return buffer.decode(encoding)

    # TODO convert_str_encoding

    def free_unicode_str(self, unicode_str):
        lib.vmi_free_unicode_str(unicode_str)

    def read_8_pa(self, paddr):
        value = ffi.new("uint8_t *")
        status = lib.vmi_read_8_pa(self.vmi, paddr, value)
        check(status)
        return value[0]

    def read_16_pa(self, paddr):
        value = ffi.new("uint16_t *")
        status = lib.vmi_read_16_pa(self.vmi, paddr, value)
        check(status)
        return value[0]

    def read_32_pa(self, paddr):
        value = ffi.new("uint32_t *")
        status = lib.vmi_read_32_pa(self.vmi, paddr, value)
        check(status)
        return value[0]

    def read_64_pa(self, paddr):
        value = ffi.new("uint64_t *")
        status = lib.vmi_read_64_pa(self.vmi, paddr, value)
        check(status)
        return value[0]

    def read_addr_pa(self, paddr):
        value = ffi.new("addr_t *")
        status = lib.vmi_read_addr_pa(self.vmi, paddr, value)
        check(status)
        return value[0]

    def read_str_pa(self, paddr):
        value = lib.vmi_read_str_pa(self.vmi,paddr)
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(value).decode()

    # write
    def write(self, ctx, buffer):
        cffi_buffer = ffi.from_buffer(buffer)
        bytes_written = ffi.new("size_t *")
        count = len(buffer)
        status = lib.vmi_write(self.vmi, ctx.to_ffi(), count, cffi_buffer, bytes_written)
        check(status)
        return bytes_written

    def write_ksym(self, symbol, buffer):
        cffi_buffer = ffi.from_buffer(buffer)
        bytes_written = ffi.new("size_t *")
        count = len(buffer)
        status = lib.vmi_write_ksym(self.vmi, symbol, count, cffi_buffer, bytes_written)
        check(status)
        return bytes_written

    def write_va(self, vaddr, pid, buffer):
        cffi_buffer = ffi.from_buffer(buffer)
        bytes_written = ffi.new("size_t *")
        count = len(buffer)
        status = lib.vmi_write_va(self.vmi, vaddr, pid, count, cffi_buffer, bytes_written)
        check(status)
        return bytes_written

    def write_pa(self, paddr, buffer):
        cffi_buffer = ffi.from_buffer(buffer)
        bytes_written = ffi.new("size_t *")
        count = len(buffer)
        status = lib.vmi_write_va(self.vmi, paddr, count, cffi_buffer, bytes_written)
        check(status)
        return bytes_written

    def write_8(self, ctx, value):
        cffi_value = ffi.new("uint8_t *", value)
        status = lib.vmi_write_8(self.vmi, ctx.to_ffi(), cffi_value)
        check(status)

    def write_16(self, ctx, value):
        cffi_value = ffi.new("uint16_t *", value)
        status = lib.vmi_write_16(self.vmi, ctx.to_ffi(), cffi_value)
        check(status)

    def write_32(self, ctx, value):
        cffi_value = ffi.new("uint32_t *", value)
        status = lib.vmi_write_32(self.vmi, ctx.to_ffi(), cffi_value)
        check(status)

    def write_64(self, ctx, value):
        cffi_value = ffi.new("uint64_t *", value)
        status = lib.vmi_write_64(self.vmi, ctx.to_ffi(), cffi_value)
        check(status)

    def write_addr(self, ctx, value):
        cffi_value = ffi.new("addr_t *", value)
        status = lib.vmi_write_addr(self.vmi, ctx.to_ffi(), cffi_value)
        check(status)

    def write_8_ksym(self, symbol, value):
        cffi_value = ffi.new("uint8_t *", value)
        status = lib.vmi_write_8_ksym(self.vmi, symbol.encode(), cffi_value)
        check(status)

    def write_16_ksym(self, symbol, value):
        cffi_value = ffi.new("uint16_t *", value)
        status = lib.vmi_write_16_ksym(self.vmi, symbol.encode(), cffi_value)
        check(status)

    def write_32_ksym(self, symbol, value):
        cffi_value = ffi.new("uint32_t *", value)
        status = lib.vmi_write_32_ksym(self.vmi, symbol.encode(), cffi_value)
        check(status)

    def write_64_ksym(self, symbol, value):
        cffi_value = ffi.new("uint64_t *", value)
        status = lib.vmi_write_64_ksym(self.vmi, symbol.encode(), cffi_value)
        check(status)

    def write_addr_ksym(self, symbol, value):
        cffi_value = ffi.new("addr_t *", value)
        status = lib.vmi_write_addr_ksym(self.vmi, symbol.encode(), cffi_value)
        check(status)

    def write_8_va(self, vaddr, pid, value):
        cffi_value = ffi.new("uint8_t *", value)
        status = lib.vmi_write_8_va(self.vmi, vaddr, pid, cffi_value)
        check(status)

    def write_16_va(self, vaddr, pid, value):
        cffi_value = ffi.new("uint16_t *", value)
        status = lib.vmi_write_16_va(self.vmi, vaddr, pid, cffi_value)
        check(status)

    def write_32_va(self, vaddr, pid, value):
        cffi_value = ffi.new("uint32_t *", value)
        status = lib.vmi_write_32_va(self.vmi, vaddr, pid, cffi_value)
        check(status)

    def write_64_va(self, vaddr, pid, value):
        cffi_value = ffi.new("uint64_t *", value)
        status = lib.vmi_write_64_va(self.vmi, vaddr, pid, cffi_value)
        check(status)

    def write_addr_va(self, vaddr, pid, value):
        cffi_value = ffi.new("addr_t *", value)
        status = lib.vmi_write_addr_va(self.vmi, vaddr, pid, cffi_value)
        check(status)

    def write_8_pa(self, paddr, value):
        cffi_value = ffi.new("uint8_t *", value)
        status = lib.vmi_write_8_pa(self.vmi, paddr, cffi_value)
        check(status)

    def write_16_pa(self, paddr, value):
        cffi_value = ffi.new("uint16_t *", value)
        status = lib.vmi_write_16_pa(self.vmi, paddr, cffi_value)
        check(status)

    def write_32_pa(self, paddr, value):
        cffi_value = ffi.new("uint32_t *", value)
        status = lib.vmi_write_32_pa(self.vmi, paddr, cffi_value)
        check(status)

    def write_64_pa(self, paddr, value):
        cffi_value = ffi.new("uint64_t *", value)
        status = lib.vmi_write_64_pa(self.vmi, paddr, cffi_value)
        check(status)

    def write_addr_pa(self, paddr, value):
        cffi_value = ffi.new("addr_t *", value)
        status = lib.vmi_write_addr_pa(self.vmi, paddr, cffi_value)
        check(status)

    # print functions
    # TODO vmi_print_hex
    # TODO vmi_print_hex_ksym
    # TODO vmi_print_hex_va
    # TODO vmi_print_hex_pa

    # get_*
    def get_name(self):
        value = lib.vmi_get_name(self.vmi)
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(value).decode()

    def get_vmid(self):
        return lib.vmi_get_vmid(self.vmi)

    def get_access_mode(self, domain, init_flags, init_data):
        if not init_flags & INIT_DOMAINNAME and not init_flags & INIT_DOMAINID:
            raise RuntimeError(
                "init_flags must be either INIT_DOMAINAME or INIT_DOMAINID")
        domain = domain.encode()
        cffi_mode = ffi.new("vmi_mode_t *")
        status = lib.vmi_get_access_mode(self.vmi, domain, init_flags, init_data, cffi_mode)
        check(status)
        return VMIMode(cffi_mode[0])

    def get_page_mode(self, vcpu):
        page_mode = lib.vmi_get_page_mode(self.vmi, vcpu)
        return PageMode(page_mode)

    def get_address_width(self):
        return lib.vmi_get_address_width(self.vmi)

    def get_ostype(self):
        os = lib.vmi_get_ostype(self.vmi)
        return VMIOS(os)

    def get_winver(self):
        win_ver = lib.vmi_get_winver(self.vmi)
        return VMIWinVer(win_ver)

    def get_winver_str(self):
        value = lib.vmi_get_winver_str(self.vmi)
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(value).decode()

    def get_winver_manual(self, kdvb_pa):
        win_ver = lib.vmi_get_winver_manual(self.vmi, kdvb_pa)
        return VMIWinVer(win_ver)

    def get_offset(self, offset_name):
        offset = ffi.new("addr_t *")
        status = lib.vmi_get_offset(self.vmi, offset_name.encode(), offset)
        check(status)
        return offset[0]

    def get_kernel_struct_offset(self, struct_name, member):
        value = ffi.new("addr_t *")
        status = lib.vmi_get_kernel_struct_offset(self.vmi, struct_name.encode(), member.encode(), value)
        check(status)
        return value[0]

    def get_memsize(self):
        return lib.vmi_get_memsize(self.vmi)

    def get_max_physical_memory_address(self):
        return lib.vmi_get_max_physical_memory_address(self.vmi)

    def get_num_vcpus(self):
        return lib.vmi_get_num_vcpus(self.vmi)

    # TODO needs a reg_t
    def get_vcpu_reg(self, reg, vcpu):
        value = ffi.new("uint64_t *")
        status = lib.vmi_get_vcpureg(self.vmi, value, reg, vcpu)
        check(status)
        return value[0]

    # TODO wrapp registers_t
    def get_vcpuregs(self, vcpu):
        registers = ffi.new("registers_t *")
        status = lib.vmi_get_vcpuregs(self.vmi, registers, vcpu)
        check(status)
        return registers

    # TODO same thing, needs a wrapper
    def set_vcpureg(self, value, reg, vcpu):
        status = lib.vmi_set_vcpureg(self.vmi, value, reg, vcpu)
        check(status)

    # TODO needs a wrapper
    def set_vcpuregs(self, regs, vcpu):
        status = lib.vmi_set_vcpuregs(regs, vcpu)
        check(status)

    def pause_vm(self):
        status = lib.vmi_pause_vm(self.vmi)
        check(status)

    def resume_vm(self):
        status = lib.vmi_resume_vm(self.vmi)
        check(status)

    # caches
    def v2pcache_flush(self, dtb=0):
        lib.vmi_v2pcache_flush(self.vmi, dtb)

    def v2pcache_add(self, va, dtb, pa):
        lib.vmi_v2pcache_add(self.vmi, va, dtb, pa)

    def symcache_flush(self):
        lib.vmi_symcache_flush(self.vmi)

    def symcache_add(self, base_addr, pid, symbol, va):
        lib.vmi_symcache_add(self.vmi, base_addr, pid, symbol.encode(), va)

    def rvacache_flush(self):
        lib.vmi_rvacache_flush(self.vmi)

    def rvacache_add(self, base_addr, pid, rva, symbol):
        lib.vmi_symcache_add(self.vmi, base_addr, pid, rva, symbol.encode())

    def pidcache_flush(self):
        lib.vmi_pidcache_flush(self.vmi)

    def pidcache_add(self, pid, dtb):
        lib.vmi_pidcache_add(self.vmi, pid, dtb)

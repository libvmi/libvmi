# Libvmi Python bindings

A Python adapter for LibVMI

If you'd rather perform introspection using Python, instead of C, then this
adapter will help get you going.

The bindings are `Python 2` compatible.

Contributors
- Bryan D. Payne
- Mathieu Tarral

## Requirements

- `python3-pkgconfig`
- `python3-cffi` (`> 1.6.0`)
- `python3-six`
- `libvmi`

## Setup

    python setup.py build
    python setup.py install

## API

### Constructor

The main class that you need to import is `Libvmi`.

The default parameters uses `VMI_CONFIG_GLOBAL_FILE_ENTRY` and calls `vmi_init_complete`:
~~~Python
from libvmi import Libvmi

with Libvmi("Windows_7") as vmi:
    os = vmi.get_ostype()
~~~

You can specify a `string` (`VMI_CONFIG_STRING`):
~~~Python
from libvmi import Libvmi, VMIConfig

config_str = '{ostype = "Windows";win_pdbase=0x28;win_pid=0x180;win_tasks=0x188;win_pname=0x2e0;}'

with Libvmi("Windows_7", mode=VMIConfig.STRING, config=config_str) as vmi:
    os = vmi.get_ostype()
~~~

Or a `dict` (`VMI_CONFIG_GHASHTABLE`):
~~~Python
from libvmi import Libvmi, VMIConfig

hash = {
    "ostype": "Windows",
    "win_pdbase": 0x28,
    "win_tasks": 0x188,
    "win_pid": 0x180,
    "win_pname": 0x2e0,
}

with Libvmi("Windows_7", mode=VMIConfig.DICT, config=hash) as vmi:
    os = vmi.get_ostype()
~~~

You can also use a `partial` initialization, which calls `vmi_init`.
(It doesn't require a configuration):
~~~Python
from libvmi import Libvmi

with Libvmi("Windows_7", partial=True) as vmi:

~~~

### Examples

~~~Python
from libvmi import Libvmi, AccessContext, TranslateMechanism

with Libvmi("Windows_7") as vmi:
    pshead = vmi.read_addr_ksym("PsActiveProcessHead")
    name = vmi.get_name()
    id = vmi.get_vmid()
    buffer, bytes_read = vmi.read_va(pshead, 4, 16)
    vmi.write_va(pshead, 4, buffer)
    ctx = AccessContext(TranslateMechanism.KERNEL_SYMBOL, ksym="PsActiveProcessHead")
    buffer, bytes_read = vmi.read(ctx, 8)
~~~


Note: The implementation already checks if the return value is `VMI_FAILURE` and
raises a `LibvmiError` in such case.


## Integration

### Volatility

You can use the [`volatlity`](https://github.com/volatilityfoundation/volatility) framework directly in top of `PyVMI` !

    git clone https://github.com/volatilityfoundation/volatility /tmp
    cp ./volatility/vmi.py /tmp/volatility/volatility/plugins/addrspaces/

Usage

    python vol.py -l vmi://domain --profile=Win7SP0x64 pslist

### Rekall

The [`Rekall`](https://github.com/google/rekall) address space is
already integrated [upstream](https://github.com/google/rekall/blob/master/rekall-core/rekall/plugins/addrspaces/vmi.py) !

Usage

    rekall -f vmi://domain pslist
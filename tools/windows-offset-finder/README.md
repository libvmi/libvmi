# Windows Offset Finder Tools
- Daniel English
- John Maccini
- Mathieu Tarral

# Method 1 - Using Rekall

The [Rekall](https://github.com/google/rekall) framework already integrate an
address space to work on top of [LibVMI](https://github.com/libvmi/libvmi).

Rekall will find the right GUID, download the PDBs and extract the right offsets for us.

## Requirements

- `LibVMI` C library
- [`libvmi` Python bindings](https://github.com/libvmi/python)
- `cabextract`

## Installing Rekall from source

At the time of this writing, there is no release of Rekall available which integrates
the new address space. Therefore you must install Rekall from source:

    virtualenv -p python3 venv
    source venv/bin/activate
    (venv) pip install --upgrade setuptools pip wheel
    (venv) git clone https://github.com/google/rekall.git
    (venv) pip install --editable rekall/rekall-lib
    (venv) pip install --editable rekall/rekall-core
    (venv) pip install --editable rekall/rekall-agent
    (venv) pip install --editable rekall

## Usage

The script `rekall_offset_finder.py` takes one argument, the `URL`, indicating how
Rekall should access the domain.
Examples:

    (venv) ./rekall_offset_finder.py vmi:///windows_7

You can specify the hypervisor if you want

    (venv) ./rekall_offset_finder.py vmi://kvm/windows_7
    (venv) ./rekall_offset_finder.py vmi://xen/windows_7


Running the script should extract the offset and display a config entry to copy paste.
Example run:


    (venv) ./rekall_offset_finder.py vmi://kvm/win7x64
    LibVMI Version 0.11.0
    LibVMI Driver Mode 1
    --completed driver init.
    --got id from name (win7x64 --> 10)
    **set image_type = win7x64
    --libvirt version 1003001
    --qmp: virsh -c qemu:///system qemu-monitor-command nitro_win7x64 '{"execute": "pmemaccess", "arguments": {"path": "/tmp/vmi0xcJEx"}}'
    --kvm: using custom patch for fast memory access
    **set allocated_ram_size = 59700000, max_physical_address = 0x59700000
     Trying to fetch http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/F8E2A8B5C9B74BF4A6E4A48F180099942/ntkrnlmp.pdb

    nitro_win7x64 {
        ostype = "Windows";
        win_pdbase = 0x28;
        win_pid = 0x180;
        win_tasks = 0x188;
        win_pname = 0x2e0;
        rekall_profile = "/home/wenzel/libvmi/tools/windows-offset-finder/win7x64-profile.json";
    }


The Rekall profile already contains the offsets displayed in the config entry.
You can choose to keep them in the config, but remember that the Rekall profile
is more complete.


Note: In the case of `Xen`, you must run the script as `root`:

    sudo venv/bin/python rekall_offset_finder.py vmi://xen/windows_7

# Method 2 - Custom scripts

This is the README file for the following suite of programs:
- getGUID.cpp
- downloadPDB.py
- dumpPDB.py
- createConfig.py


## Dependencies

These tools require a variety of dependencies.  Below is a list of everything
that you will need, including the commands needed to install each dependency
on a Debian system.

- `pdbparse`


    svn checkout http://pdbparse.googlecode.com/svn/trunk/ pdbparse-read-only
    cd pdbparse-read-only/
    sudo python setup.py install

- `python-pefile`


    sudo apt-get install python-pefile

- `mscompress`


    sudo apt-get install mscompress

- `cabextract`


    sudo apt-get install cabextract

- `python construct`


    sudo apt-get install python-pip
    sudo pip install construct


## Tools Description


### getGUID.cpp

A C++ source file that must be compiled and run as a program from the
command line with a memory image file supplied as the only argument. This
program searches through the memory image for the Windows kernel and uses
known information about Windows operating system memory layout to obtain the
OS's GUID and .pdb filename from the memory dump. Currently, the tool works
for any 32-bit NT-based OS, XP or newer. Windows 2000 is not known to be
compatible because that OS uses an older format of debug file known as a .dbg
file. The tool will recognize this and display a message to that effect.

Use the following command to compile this program:

    g++ -o getGUID getGUID.cpp

### downloadPDB.py

A Python script that runs from the command line with piped input from
getGUID.  It will access the Microsoft Symbol Server and download the
.pdb file associated with the GUID and filename.  Note that since .pdb
files downloaded from the server are compressed, downloadPDB requires
that cabextract be installed in order to function properly. In addition,
to handle Windows 7 .pdb files, msexpand is required (since these .pdb
files use a different compression format). This tool uses an open source
library called PDBParse which can be found at
http://code.google.com/p/pdbparse/.

### dumpPDB.py

A Python script that runs from the command line with either piped input
from downloadPDB or with a supplied .pdb filename. This tool uses PDBParse
to parse the .pdb file and dumps relevant information into a
comma-separated-values text file at a supplied output filename.

### createConfig.py

A Python script that build a libvmi.conf config file entry based on
the output from dumpPDB.


## Inputs and Flags

Note: using -h with any tool will display a help message with descriptions of
available flags.

`getGUID`: Requires an input filename (memory image). No other options.

`downloadPDB.py`: Input must be piped from getGUID.  The -v option enables
verbose output and displays a download progress bar and other status messages.

`dumpPDB`: Input can be either piped or given as a .pdb file with the -f option.
The -o flag must be supplied with an output filename in both cases.

`createConfig`: Input is the filename output from dumpPDB, given with the -f
option.


## Examples

### Memory Aquisition

To start, these programs require a raw memory dump from the system you are
wanting to build a config file.  You can use the example program `dump-memory`
from libvmi to obtain this dump:

    ./examples/dump-memory winxpsp2 winxp.dd

This example will create a raw memory dump from the virtual machine named
`winxpsp2` and save it as `winxps.dd`.

Another option is to use memory forensics tools to create this memory dump.
For more details see http://www.moonsols.com/windows-memory-toolkit/.

The examples below assume that you have created such a file called 'winxp.dd'
and copied it into the ./tools/windows-offset-finder/ directory.

### Create debug symbols CSV

    ./getGUID winxp.dd |./downloadPDB.py | ./dumpPDB.py -o debugSymbols.txt

### Create LibVMI config file entry

    ./createConfig.py -f debugSymbols.txt
    <vm name> {
        ostype = "Windows";
        win_tasks   = 0x88;
        win_pdbase  = 0x18;
        win_pid     = 0x84;
    }

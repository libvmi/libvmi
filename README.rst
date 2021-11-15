LibVMI: Simplified Virtual Machine Introspection
================================================

LibVMI is a virtual machine introspection library.  This means that it helps
you access the memory of a running virtual machine.  LibVMI provides primitives
for accessing this memory using physical or virtual addresses and kernel
symbols.  LibVMI also supports accessing memory from a physical memory snapshot,
which is helpful for debugging or forensic analysis.

In addition to memory access, LibVMI supports memory events.  Events provide
notifications when registered regions of memory are executed, written to, or
read.  Memory events require hypervisor support and are currently only
available with Xen.

LibVMI is designed to run on Linux (file, Xen, or KVM access) or Mac OS X
(file access only).  The most used platform is Linux + Xen, but the
others are well tested and worth exploring as well.  LibVMI can provide access
to physical memory for any operating system, and access to virtual memory and
kernel symbols from Windows and Linux.

If you would like higher level semantic information, then we suggest using the
LibVMI Python bindings and Volatility.  Volatility
(https://github.com/volatilityfoundation/volatility/) is a forensic memory
analysis framework supporting both Linux and Windows systems that can aid
significantly in performing useful memory analysis tasks.  The LibVMI Python
bindings includes a Volatility address space plugin that enables you to use
Volatility on a live virtual machine.

This file contains very basic instructions to get you up and running.  If you
want more details about installation, or programming with LibVMI, then see
the documentation included in the doc/ subdirectory of LibVMI, or view the
documentation online at http://www.libvmi.com.

.. image:: https://badges.gitter.im/Join%20Chat.svg
   :alt: Join the chat at https://gitter.im/libvmi/Lobby
   :target: https://gitter.im/libvmi/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge

.. image:: https://github.com/libvmi/libvmi/actions/workflows/compile.yml/badge.svg
    :target: https://github.com/libvmi/libvmi/actions/workflows/compile.yml

.. image:: https://scan.coverity.com/projects/14159/badge.svg
    :target: https://scan.coverity.com/projects/libvmi-libvmi

Dependencies
------------
The following libraries are used in building this code:

- ``CMake`` (``>= 3.1``)

- ``libtool`` Generic library support script

- ``yacc`` OR ``bison`` (optional, for reading the configuration file)

- ``lex`` OR ``flex`` (optional, for reading the configuration file)

- ``glib`` (``>= 2.22``)

- ``libvirt`` (``>= 0.8.7``)

- ``libjson-c``

Installing the dependencies on Ubuntu::

    $ sudo apt-get install cmake flex bison libglib2.0-dev libvirt-dev libjson-c-dev libyajl-dev

Building
--------
LibVMI uses the [CMake](https://cmake.org/) build system.  To compile this library, simply
follow the steps below:

.. code::

   mkdir build
   cd build
   cmake ..
   make

The example code will work without installing LibVMI.

You can specify a different install prefix with
``cmake -DCMAKE_INSTALL_PREFIX=/usr ..``

The default installation prefix is ``/usr/local``.  You may need to run
``ldconfig`` after performing a ``make install``.

For a complete view of the build options, using ``ccmake`` tool is prefered if
available.

Otherwise, look at ``CMakeLists.txt`` ``option()`` commands.

Installation and Configuration
------------------------------
For complete details on installation and configuration, please see the
related online documentation:

http://libvmi.com/docs/gcode-install.html

Xen support
~~~~~~~~~~~

LibVMI provides support for Xen out-of-the-box. If you install Xen from source,
make sure the Xen libraries compiled from source are in your LD_LIBRARY_PATH. You don't
have to recompile LibVMI if you update Xen as LibVMI is able to detect what version of Xen
you have dynamically at runtime.

XenServer Support
-----------
Compiling LibVMI on a XenServer dom0 can be challenging as there are no
development headers and tools present. The recommended way to compile
is in a separate CentOS installation using the Xen development packages
matching what XenServer runs on. The compiled LibVMI library and tools
can then be transferred to the XenServer dom0 and run natively.

KVM support
~~~~~~~~~~~
The KVM driver for LibVMI is based on the new ``KVMi`` subsystem for
KVM, which aims to bring an official VMI API on this hypervisor.

The current state of these KVM patches is a work-in-progress, but it is mature
enough to be proposed by default in LibVMI, instead of using previous memory access
methods (GDB stub or the ``tools/qemu-kvm-patch`` memaccess custom patches for QEMU).

In order to use the LibVMI KVM driver, you will have to setup ``KVM-VMI`` beforehand.
KVM-VMI is a Github community dedicated to bring a native VMI API on KVM, and
currently hosting this new API:

https://github.com/KVM-VMI/kvm-vmi

The installation guide can be found at the following link:

https://kvm-vmi.github.io/kvm-vmi/kvmi-v7/setup.html

KVM legacy driver support:

To enable the old KVM memory access methods (GDB stub and QEMU fast-memaccess
patches), you need to add the ``-DENABLE_KVM_LEGACY`` CMake command line
argument.

   cd build
   cmake .. -DENABLE_KVM_LEGACY


Python bindings
----------------
LibVMI is written in C.  If you would rather work with Python, then look at the
``libvmi/python``` repository. They provide an almost feature complete python
interface to LibVMI with a relatively small performance overhead.

https://github.com/libvmi/python

File / Snapshot Support
-----------------------
If you would like LibVMI to work on physical memory snapshots saved to
a file, then you don't need any special setup.

Volatility3 Intermediate Symbol Table (IST) Format
------------------------------
LibVMI supports the use of Volatility3's IST JSONs for introspecting Windows and Linux. By using
these jsons, LibVMI is able to bypass the use if the in-memory KdDebuggerData (KDBG)
structure normally used by memory forensics tools and thus allows introspecting domains
where this structure is either corrupted, or encoded (like in the case of Windows 8 x64).
However, these ISTs have to be created for each kernel version, and therefore if an
update is made to the kernel, the JSON file has to be re-generated, thus it's a bit less stable
as the standard LibVMI configuration entries.

Volatility3 is available at https://github.com/volatilityfoundation/volatility3.

To read about how to generate the IST see: https://volatility3.readthedocs.io/en/latest/symbol-tables.html.

Note: To support Linux profiles generated by dwarf2json you'll need libjson-c version 0.15 or newer installed.

Rekall profiles
------------------------------
Note: Rekall is no longer maintained. Support for Rekall profiles will be deprecated.

LibVMI also supports the use of Rekall profiles for introspecting Windows and Linux. By using
Rekall profiles, LibVMI is able to bypass the use if the in-memory KdDebuggerData (KDBG)
structure normally used by memory forensics tools and thus allows introspecting domains
where this structure is either corrupted, or encoded (like in the case of Windows 8 x64).
However, Rekall profiles have to be created for each kernel version, and therefore if an
update is made to the kernel, the profile has to be re-generated, thus it's a bit less stable
as the standard LibVMI configuration entries.

Rekall is available at https://github.com/google/rekall.

To create a Rekall profile for Windows you can use the rekall_offset_finder.py script that ships
with LibVMI. See https://github.com/libvmi/libvmi/blob/master/tools/windows-offset-finder for more
details. If you need to examine an on-disk version of the kernel (or any other PE executable), you
can run the following the Rekall command:

.. code::

    rekall peinfo -f <path/to/ntoskrnl.exe>


Once the PDB filename and GUID is known, creating the Rekall profile is done in two steps:

.. code::

    rekall fetch_pdb <PDB filename> <GUID>
    rekall parse_pdb <PDB filename> > rekall-profile.json

The PDB filename should not have the .pdb extension in the above commands.

To create a Rekall profile for Linux follow the instructions at https://github.com/google/rekall/tree/master/tools/linux

The Rekall profile can be used directly in the LibVMI config via an additional rekall_profile entry
pointing to this file with an absolute path. There is no need to specify any of the offsets normally
required as those offsets will be available via the profile itself.

Debugging
---------
To enable LibVMI debug output, look at the ``libvmi/debug.h`` header file,
and set the CMake ``VMI_DEBUG`` option accordingly.

Example to enable all debug output:

.. code::

    cmake -DVMI_DEBUG=__VMI_DEBUG_ALL ..

Example to enable selective output (XEN and CORE)

.. code::

    cmake -DVMI_DEBUG='(VMI_DEBUG_XEN | VMI_DEBUG_CORE)' ..

Community
---------
The LibVMI forums are available at https://groups.google.com/forum/#!forum/vmitools

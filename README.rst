LibVMI: Simplified Virtual Machine Introspection
================================================
LibVMI is a virtual machine introspection library.  This means that it helps 
you access the memory of a running virtual machine.  LibVMI provides primatives
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

If you would like higher level semantic information, then we suggest using 
LibVMI with PyVMI (python wrapper, included with LibVMI) and Volatility.
Volatility (http://code.google.com/p/volatility/) is a forensic memory analysis
framework supporting both Linux and Windows systems that can aid significantly
in performing useful memory analysis tasks.  PyVMI includes a Volatility
address space plugin that enables you to use Volatility on a live virtual 
machine.

This file contains very basic instructions to get you up and running.  If you
want more details about installation, or programming with LibVMI, then see
the documentation included in the doc/ subdirectory of LibVMI, or view the
documentation online at http://www.libvmi.com.


Dependencies
------------
The following libraries are used in building this code:

- libxc (from Xen, the Xen Control library, required for Xen support)

- libxenstore (from Xen, access to the xenstore, required for Xen support)

- libvirt (from Red Hat, access to KVM guests, 0.8.7 or newer required for KVM
  support, MUST BE BUILT WITH QMP SUPPORT -- THIS REQUIRES yajl)

- qemu-kvm patch (option 1 for KVM memory access, optional for KVM support,
  still buggy but faster than alternative option, see Note 2)

- gdb enabled kvm VM (option 2 for KVM memory access, optional for KVM
  support, more stable than option 1 but slower, see Note 2)

- yacc OR bison (for reading the configuration file)

- lex OR flex (for reading the configuration file)

- glib (version 2.22 or better is required)

Note 1: If you are installing a packaged version of Xen, you will likely
need to install something like 'xen-devel' to obtain the files needed
from libxc and libxenstore in the dependencies listed above.

Note 2: If you want KVM support then you will need to build your own 
version of QEMU-KVM or enable GDB support for your VM.  See the
section on KVM support (below) for additional information.


Installation and Configuration
------------------------------
For complete details on installation and configuration, please see the
related online documentation: 

http://code.google.com/p/vmitools/wiki/LibVMIInstallation


Python Interface
----------------
LibVMI is written in C.  If you would rather work with Python, then look at
the tools/pyvmi/ directory after installing LibVMI.  PyVMI provides a
feature complete python interface to LibVMI with a relatively small
performance overhead.


Xen Support
-----------
If you would like LibVMI to work on Xen domains, you must simply ensure
that you have Xen installed along with any Xen development packages.
LibVMI should effectively just work on any recent version of Xen.


KVM Support
-----------
If you would like LibVMI to work on KVM VM's, you must do some additional
setup.  This is because KVM doesn't have much built-in capability for
introspection.  For KVM support you need to do the following:

- Ensure that you have libvirt version 0.8.7 or newer

- Ensure that your libvirt installation supports QMP commands, most 
  prepackaged versions do not support this by default so you may need
  to install libvirt from source yourself.  To enable QMP support 
  when installing from source, ensure that you have libyajl-dev (or 
  the equivalent from your linux distro) installed, then run the
  configure script from libvirt.  Ensure that the configure script
  reports that it found yajl.  Then run make && make install.

- Choose a memory access technique:

  1) Patch QEMU-KVM with the provided patch.  This technique will 
     provide the fastest memory access, but is buggy and may cause
     your VM to crash / lose data / etc.  To use this method, 
     follow the instructions in the libvmi/tools/qemu-kvm-patch
     directory.

  2) Enable GDB access to your KVM VM.  This is done by adding
     '-s' to the VM creation line or, by modifying the VM XML
     definition used by libvirt as follows:

     - Change:
       
       .. code::
       
          <domain type='kvm'>
          
       to:

       .. code::

           <domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>

     - Add:

       .. code::

           <qemu:commandline>
             <qemu:arg value='-s'/>
           </qemu:commandline>

       under the <domain> level of the XML.

- You only need one memory access technique.  LibVMI will first look
  for the QEMU-KVM patch and use that if it is installed.  Otherwise
  it will fall back to using GDB.  So if you want to use GDB, you 
  should both enable GDB and ensure that QEMU-KVM does not have the
  LibVMI patch.


File / Snapshot Support
-----------------------
If you would like LibVMI to work on physical memory snapshots saved to
a file, then you don't need any special setup.


Shm-snapshot Support
------------------------------
(Don't mix up with VM snapshot file) This technique will provide a very 
fast and coherent memory access, except the creation of shm-snapshot can take
0.2 ~ 1.4 seconds (KVM) when the memory size of guest VM expands from 512MB to 
3GB. 
Shm-snapshot supports both KVM and Xen. However,shm-snapshot for Xen is 
currently created by LibVMI, hence unreal. Moreover,it takes more time (about 3 
seconds in 1GB guest memory settings) to create Xen "shm-snapshot" because we 
have to probe unmmapable memory page holes one by one.
Shm-snapshot is shiped with direct guest memory access, a non-copy access technique
that can drastically reduce the latency of guest memory access. For KVM, we support
both vmi_get_dgpma() and vmi_get_dgvma(); for Xen, however, due to the unreal 
shm-snapshot, we only support vmi_get_dgpma() now.

If you would like LibVMI to work on a shm-snapshot, then you need to do the 
following:

(P.S: If you use Xen, just to start on step 3)

1. ensure that your libvirt installation supports QMP commands.

2. patch QEMU-KVM with the provided shm-snapshot patch.  
    cd qemu-1.6
    patch -p1 < [libvmi_dir]/tools/qemu-kvm-patch/kvm-physmem-access-physmem-snapshot_1.6.0.patch
    make
    make install
  
3. ./configure --enable-shm-snapshot

4. Choose a setup method :
  1) Add VMI_INIT_SHM_SNAPSHOT flag to vmi_int(), then vmi_init() will create 
     a shm-snapshot and enter shm-snapshot mode automatically. Once LibVMI enters 
     the shm-snapshot mode, memory access will be redirect to the shared memory 
     shm-snapshot, rather than your live guest VM.
  
  2) After the vmi_init() has been called, invoke vmi_snapshot_create(vmi)
     to snaphsot your guest VM and enter shm-snapshot mode.
  
  No matter which method you choose, you can turn LibVMI back to live mode 
  by calling vmi_shm_snapshot_destroy(vmi).
  
  Even if you didn't call vmi_shm_snapshot_destroy(vmi), vmi_destroy(vmi) will 
  teardown the shm-snapshot if existed.

5. (optional but valuable) replace your guest memory access function.
  If you ever used vmi_read_pa() like the following:
    void* buf = malloc(100);
    int size = vmi_read_pa(vmi, 0x1000, buf, 100);
    process_anything(buf, size);
    free(buf);
  Just feel free to change your code like the following:
    void* buf = NULL;
    int size = vmi_get_dgpma(vmi, 0x1000, &buf, 100);
    process_anything(buf, size);
  For vmi_read_va(), the replacement is very similar, but only capable for
  KVM at present.
    

Building
--------
LibVMI uses the standard GNU build system.  To compile this library, simply
follow the steps below:

.. code::

   ./autogen.sh
   ./configure
   make

The example code will work without installing LibVMI.  However, you may
choose to install the library into the prefix specified to 'configure' by:

make install

The default installation prefix is /usr/local.  You may need to run
'ldconfig' after performing a 'make install'.


Transition from XenAccess
-------------------------
If you are just making the transition form XenAccess, please see the transition
documentation online:

http://code.google.com/p/vmitools/wiki/TransitionFromXenAccess

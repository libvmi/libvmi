SUBDIRS = config

h_public =  libvmi.h \
            libvmi_extra.h \
            x86.h

h_private = \
    private.h \
    debug.h \
    glib_compat.h \
    rekall.h \
    arch/arch_interface.h \
    arch/intel.h \
    arch/amd64.h \
    arch/arm_aarch32.h \
    arch/arm_aarch64.h \
    os/os_interface.h \
    driver/driver_interface.h \
    driver/driver_wrapper.h \
    driver/memory_cache.h

c_sources = \
    accessors.c \
    cache.c \
    convenience.c \
    core.c \
    events.c \
    performance.c \
    pretty_print.c \
    read.c \
    strmatch.c \
    write.c \
    memory.c \
    arch/arch_interface.c \
    arch/intel.c \
    arch/amd64.c \
    arch/arm_aarch32.c \
    arch/arm_aarch64.c \
    driver/driver_interface.c \
    driver/memory_cache.c \
    os/os_interface.c

if REKALL_PROFILES
c_sources  += rekall.c
endif

if SHM
h_public    += shm.h
c_sources   += shm.c
endif

drivers =
if HAVE_FILE
drivers     += driver/file/file.h \
               driver/file/file_private.h \
               driver/file/file.c
endif
if HAVE_KVM
drivers     += driver/kvm/kvm.h \
               driver/kvm/kvm_private.h \
               driver/kvm/kvm.c
if SHM
drivers     += driver/kvm/kvm_shm.h
endif
endif

if HAVE_XEN
h_public    += events.h
drivers     += driver/xen/xen.h \
               driver/xen/xen_private.h \
               driver/xen/xen.c \
               driver/xen/xen_events.h \
               driver/xen/xen_events_private.h \
               driver/xen/xen_events.c \
               driver/xen/xen_events_legacy.c \
               driver/xen/libxc_wrapper.c
endif

os =
if WINDOWS
h_public    += peparse.h
os          += os/windows/windows.h \
               os/windows/core.c \
               os/windows/kdbg.c \
               os/windows/memory.c \
               os/windows/peparse.c \
               os/windows/process.c \
               os/windows/unicode.c
endif
if LINUX
os          += os/linux/linux.h \
               os/linux/core.c \
               os/linux/memory.c \
               os/linux/symbols.c
endif

library_includedir=$(includedir)/$(LIBRARY_NAME)
library_include_HEADERS = $(h_public)

AM_CFLAGS = -I$(top_srcdir)
AM_CPPFLAGS = -I$(top_srcdir)

lib_LTLIBRARIES= libvmi.la
libvmi_la_SOURCES= $(h_public) $(h_private) $(drivers) $(os) $(c_sources)
libvmi_la_LIBADD= config/libconfig.la
libvmi_la_CFLAGS= -fvisibility=hidden $(GLIB_CFLAGS)
libvmi_la_CFLAGS+= -Werror -Wall -Wextra -Wno-missing-field-initializers
libvmi_la_LDFLAGS= -release $(RELEASE) $(GLIB_LIBS)

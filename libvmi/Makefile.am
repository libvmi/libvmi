h_public =  libvmi.h \
            libvmi_extra.h \
            slat.h \
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
    convenience.c \
    core.c \
    events.c \
    performance.c \
    pretty_print.c \
    read.c \
    slat.c \
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

if ENABLE_ADDRESS_CACHE
c_sources  += cache.c
endif

if REKALL_PROFILES
c_sources  += rekall.c
endif

if SHM
h_public    += shm.h
c_sources   += shm.c
endif

drivers =
if WITH_FILE
drivers     += driver/file/file.h \
               driver/file/file_private.h \
               driver/file/file.c
endif
if WITH_KVM
drivers     += driver/kvm/kvm.h \
               driver/kvm/kvm_private.h \
               driver/kvm/kvm.c \
               driver/kvm/libvirt_wrapper.c \
               driver/kvm/libvirt_wrapper.h
if SHM
drivers     += driver/kvm/kvm_shm.h
endif
endif

if WITH_XEN
h_public    += events.h
drivers     += driver/xen/altp2m.c \
               driver/xen/altp2m_private.h \
               driver/xen/xen.h \
               driver/xen/xen_private.h \
               driver/xen/xen.c \
               driver/xen/xen_events.c \
               driver/xen/xen_events.h \
               driver/xen/xen_events_private.h \
               driver/xen/xen_events_46.c \
               driver/xen/xen_events_48.c \
               driver/xen/xen_events_legacy.c \
               driver/xen/libxc_wrapper.c \
               driver/xen/libxc_wrapper.h \
               driver/xen/libxs_wrapper.c \
               driver/xen/libxs_wrapper.h
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
if FREEBSD
os          += os/freebsd/freebsd.h \
               os/freebsd/core.c \
               os/freebsd/memory.c \
               os/freebsd/symbols.c
endif


library_includedir=$(includedir)/$(LIBRARY_NAME)
library_include_HEADERS = $(h_public)

AM_CFLAGS = -I$(top_srcdir)
AM_CPPFLAGS = -I$(top_srcdir)

lib_LTLIBRARIES= libvmi.la
libvmi_la_SOURCES= $(h_public) $(h_private) $(drivers) $(os) $(c_sources)
libvmi_la_CFLAGS= -fvisibility=hidden $(GLIB_CFLAGS)
libvmi_la_CFLAGS+= -Wall -Wextra
libvmi_la_LDFLAGS= $(GLIB_LIBS) -no-undefined
libvmi_la_LDFLAGS+= -version-info $(VERSION)

if CONFIGFILE
libvmi_la_LIBADD= config/libconfig.la
endif

if DEBUG
libvmi_la_CFLAGS+= -Werror
libvmi_la_CFLAGS+= -Wno-missing-field-initializers
libvmi_la_CFLAGS+= -Wno-missing-braces
libvmi_la_CFLAGS+= -Wno-unused-result
libvmi_la_CFLAGS+= -Wno-ignored-attributes
endif

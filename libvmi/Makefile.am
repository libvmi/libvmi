SUBDIRS = config
h_sources = libvmi.h libvmi_extra.h peparse.h x86.h
h_private = \
    private.h \
    debug.h \
    glib_compat.h \
    arch/arch_interface.h \
    arch/intel.h \
    arch/amd64.h \
    os/os_interface.h \
    os/windows/windows.h \
    os/linux/linux.h \
    driver/interface.h \
    driver/memory_cache.h \
    driver/file.h \
    driver/xen.h \
    driver/xen_events.h \
    driver/xen_private.h \
    driver/kvm.h
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
    driver/file.c \
    driver/interface.c \
    driver/kvm.c \
    driver/memory_cache.c \
    driver/xen.c \
    driver/xen_events.c \
    os/os_interface.c \
    os/linux/core.c \
    os/linux/memory.c \
    os/linux/symbols.c \
    os/windows/core.c \
    os/windows/kdbg.c \
    os/windows/memory.c \
    os/windows/symbols.c \
    os/windows/peparse.c \
    os/windows/process.c \
    os/windows/unicode.c

library_includedir=$(includedir)/$(LIBRARY_NAME)
library_include_HEADERS = $(h_sources)

AM_CPPFLAGS = -I$(top_srcdir)

lib_LTLIBRARIES= libvmi.la
libvmi_la_SOURCES= $(h_sources) $(h_private) $(c_sources)
libvmi_la_LIBADD= config/libconfig.la
libvmi_la_CFLAGS= -fvisibility=hidden $(GLIB_CFLAGS) $(JANSSON_CFLAGS)
libvmi_la_LDFLAGS= -release $(RELEASE) $(GLIB_LIBS) $(JANSSON_LIBS)
libvmi_la_DEPENDENCIES= libvmi.h

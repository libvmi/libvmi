SUBDIRS = config

h_sources = libvmi.h libvmi_extra.h peparse.h
c_sources = \
    accessors.c \
    cache.c \
    convenience.c \
    core.c \
    events.c \
    memory.c \
    performance.c \
    pretty_print.c \
    read.c \
    strmatch.c \
    write.c \
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
    os/windows/peparse.c \
    os/windows/process.c

library_includedir=$(includedir)/$(LIBRARY_NAME)
library_include_HEADERS = $(h_sources)

AM_CPPFLAGS = -I$(top_srcdir)

lib_LTLIBRARIES= libvmi.la
libvmi_la_SOURCES= $(h_sources) $(c_sources)
libvmi_la_LIBADD= config/libconfig.la
libvmi_la_CFLAGS= -fvisibility=hidden $(GLIB_CFLAGS)
libvmi_la_LDFLAGS= -release $(RELEASE) $(GLIB_LIBS)
libvmi_la_DEPENDENCIES= libvmi.h

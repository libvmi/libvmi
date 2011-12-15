SUBDIRS = config

h_sources = libvmi.h
c_sources = \
    accessors.c \
    cache.c \
    convenience.c \
    core.c \
    memory.c \
    pretty_print.c \
    read.c \
    strmatch.c \
    write.c \
    driver/file.c \
    driver/interface.c \
    driver/kvm.c \
    driver/memory_cache.c \
    driver/xen.c \
    os/linux/core.c \
    os/linux/memory.c \
    os/linux/symbols.c \
    os/windows/core.c \
    os/windows/kpcr.c \
    os/windows/memory.c \
    os/windows/peparse.c \
    os/windows/process.c

library_includedir=$(includedir)/$(LIBRARY_NAME)
library_include_HEADERS = $(h_sources)

INCLUDES = -I$(top_srcdir)

lib_LTLIBRARIES= libvmi.la
libvmi_la_SOURCES= $(h_sources) $(c_sources)
libvmi_la_LIBADD= config/libconfig.la
libvmi_la_CFLAGS= -fvisibility=hidden $(GLIB_CFLAGS)
libvmi_la_LDFLAGS= -release $(RELEASE) $(GLIB_LIBS)
libvmi_la_DEPENDENCIES= libvmi.h

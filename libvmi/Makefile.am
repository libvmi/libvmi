SUBDIRS = config

h_sources = libvmi.h
c_sources = \
    core.c \
    accessors.c \
    memory.c \
    cache.c \
    pretty_print.c \
    util.c \
    symbols.c \
    os/linux/core.c \
    os/linux/symbols.c \
    os/linux/memory.c \
    os/windows/core.c \
    os/windows/memory.c \
    os/windows/peparse.c \
    os/windows/process.c \
    driver/interface.c \
    driver/xen.c

library_includedir=$(includedir)/$(LIBRARY_NAME)
library_include_HEADERS = $(h_sources)

INCLUDES = -I$(top_srcdir)

lib_LTLIBRARIES= libvmi.la
libvmi_la_SOURCES= $(h_sources) $(c_sources)
libvmi_la_LIBADD= config/libconfig.la
libvmi_la_LDFLAGS= -release $(RELEASE)
libvmi_la_DEPENDENCIES= libvmi.h

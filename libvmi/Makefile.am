SUBDIRS = config

h_sources = libvmi.h xa_private.h
c_sources = linux_core.c linux_domain_info.c linux_symbols.c xa_core.c xa_memory.c linux_memory.c xa_cache.c xa_domain_info.c xa_file.c xa_pretty_print.c xa_util.c windows_memory.c windows_core.c windows_process.c xa_symbols.c xa_error.c windows_peparse.c

library_includedir=$(includedir)/$(LIBRARY_NAME)
library_include_HEADERS = $(h_sources)

INCLUDES = -I$(top_srcdir)

lib_LTLIBRARIES= libvmi.la
libvmi_la_SOURCES= $(h_sources) $(c_sources)
libvmi_la_LIBADD= config/libconfig.la
libvmi_la_LDFLAGS= -release $(RELEASE)
libvmi_la_DEPENDENCIES= libvmi.h

BUILT_SOURCES= libvmi.h
CLEANFILES= libvmi.h

if XEN
do_subst1= $(SED) -r '/\#ifdef ENABLE_XEN/,/\#endif/ s/(^\#ifdef|^\#endif)/\/\/&/'
else
do_subst1= $(SED) '/\#ifdef ENABLE_XEN/,/\#endif/ s/^.*/\/\/&/'
endif

if KVM
do_subst2= $(SED) -r '/\#ifdef ENABLE_KVM/,/\#endif/ s/(^\#ifdef|^\#endif)/\/\/&/'
else
do_subst2= $(SED) '/\#ifdef ENABLE_KVM/,/\#endif/ s/^.*/\/\/&/'
endif

libvmi.h: libvmi.h.in
	$(do_subst1) < libvmi.h.in > libvmi.h.in2
	$(do_subst2) < libvmi.h.in2 > libvmi.h

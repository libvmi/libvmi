SUBDIRS = config

h_sources = xenaccess.h xa_private.h
c_sources = linux_core.c linux_domain_info.c linux_symbols.c xa_core.c xa_memory.c linux_memory.c xa_cache.c xa_domain_info.c xa_file.c xa_pretty_print.c xa_util.c windows_memory.c windows_core.c windows_process.c xa_symbols.c xa_error.c windows_peparse.c

library_includedir=$(includedir)/$(LIBRARY_NAME)
library_include_HEADERS = $(h_sources)

INCLUDES = -I$(top_srcdir)

lib_LTLIBRARIES= libxenaccess.la
libxenaccess_la_SOURCES= $(h_sources) $(c_sources)
libxenaccess_la_LIBADD= config/libconfig.la
libxenaccess_la_LDFLAGS= -release $(RELEASE)
libxenaccess_la_DEPENDENCIES= xenaccess.h

BUILT_SOURCES= xenaccess.h
CLEANFILES= xenaccess.h

if XEN
do_subst= $(SED) -r '/\#ifdef ENABLE_XEN/,/\#endif/ s/(^\#ifdef|^\#endif)/\/\/&/'
else
do_subst= $(SED) '/\#ifdef ENABLE_XEN/,/\#endif/ s/^.*/\/\/&/'
endif

xenaccess.h: xenaccess.h.in
	$(do_subst) < xenaccess.h.in > xenaccess.h

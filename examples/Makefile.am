## Source directory

SUBDIRS = 

INCLUDES = -I$(top_srcdir)
AM_LDFLAGS = -L$(top_srcdir)/libvmi/.libs/
LDADD = -lvmi $(LIBS)

bin_PROGRAMS = module-list process-data process-list map-symbol map-addr dump-memory
module_list_SOURCES = module-list.c
process_data_SOURCES = process-data.c
process_list_SOURCES = process-list.c
map_symbol_SOURCES = map-symbol.c
map_addr_SOURCES = map-addr.c
dump_memory_SOURCES = dump-memory.c


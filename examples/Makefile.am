## Source directory

SUBDIRS = 

AM_CPPFLAGS = -I$(top_srcdir)
AM_LDFLAGS = -L$(top_srcdir)/libvmi/.libs/
LDADD = -lvmi -lm $(LIBS)

bin_PROGRAMS = module-list process-list map-symbol map-addr dump-memory win-guid event-example
module_list_SOURCES = module-list.c
process_list_SOURCES = process-list.c
map_symbol_SOURCES = map-symbol.c
map_addr_SOURCES = map-addr.c
dump_memory_SOURCES = dump-memory.c
event_example_SOURCES = event-example.c
win_guid_SOURCES = win-guid.c


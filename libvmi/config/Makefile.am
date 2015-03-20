h_sources = config_parser.h
c_sources = grammar.y lexicon.l

CLEANFILES = lexicon.c grammar.c grammar.h
AM_CFLAGS = -I$(top_srcdir)
AM_CPPFLAGS = -I$(top_srcdir)

AM_YFLAGS = -y -d

noinst_LTLIBRARIES= libconfig.la
libconfig_la_SOURCES= $(h_sources) $(c_sources)
libconfig_la_CFLAGS= $(GLIB_CFLAGS)
libconfig_la_LDFLAGS= $(GLIB_LIBS)

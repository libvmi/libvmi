h_sources = config_parser.h
c_sources = grammar.y lexicon.l

CLEANFILES = lexicon.c grammar.c grammar.h
INCLUDES = -I$(top_srcdir)
AM_YFLAGS = -y -d

noinst_LTLIBRARIES= libconfig.la
libconfig_la_SOURCES= $(h_sources) $(c_sources)

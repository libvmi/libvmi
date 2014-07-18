## Source directory

SUBDIRS = 

AM_CPPFLAGS = -I$(top_srcdir) $(GLIB_CFLAGS) $(FUSE_CFLAGS) -DFUSE_USE_VERSION=22
AM_LDFLAGS = -L$(top_builddir)/libvmi/.libs/
LDADD = -lvmi -lm $(LIBS) $(GLIB_LIBS) $(FUSE_LIBS)

bin_PROGRAMS = vmifs
vmifs_SOURCES = vmifs.c


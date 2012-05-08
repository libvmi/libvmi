# top level directory
# Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

#Build in these directories:
SUBDIRS= $(LIBRARY_NAME) examples tests

#Distribute these directories:
DIST_SUBDIRS = $(LIBRARY_NAME) examples

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libvmi.pc

EXTRA_DIST=autogen.sh

# top level directory
# Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

#Build in these directories:
SUBDIRS= @config_dir@ $(LIBRARY_NAME) @examples_dir@ @test_dir@ @vmifs_dir@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libvmi.pc

EXTRA_DIST=autogen.sh

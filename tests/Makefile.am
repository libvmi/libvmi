AUTOMAKE_OPTIONS = no-dependencies
TESTS = check_libvmi

check_PROGRAMS = check_libvmi

check_libvmi_SOURCES = \
    check_runner.c \
    check_tests.h \
    test_accessor.c \
    test_init.c \
    test_print.c \
    test_read.c \
    test_translate.c \
    test_util.c \
    test_write.c \
    test_peparse.c \
    test_shm_snapshot.c \
    test_cache.c \
    test_getvapages.c \
    $(top_builddir)/libvmi/cache.c \
    $(top_builddir)/libvmi/convenience.c

check_libvmi_CFLAGS = @CHECK_CFLAGS@ @GLIB_CFLAGS@ -I$(top_srcdir) -I$(top_srcdir)/libvmi/
check_libvmi_LDADD = $(top_builddir)/libvmi/libvmi.la @CHECK_LIBS@ @GLIB_LIBS@
check_libvmi_DEPENDENCIES = $(top_srcdir)/libvmi/cache.c $(top_srcdir)/libvmi/convenience.c

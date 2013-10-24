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
    ../libvmi/cache.c \
    ../libvmi/convenience.c \
    $(top_builddir)/libvmi/libvmi.h

check_libvmi_CFLAGS = @CHECK_CFLAGS@ @GLIB_CFLAGS@ -I../libvmi/
check_libvmi_LDADD = $(top_builddir)/libvmi/libvmi.la @CHECK_LIBS@

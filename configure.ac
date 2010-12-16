dnl --------------------------------
dnl Initialization macros.
dnl --------------------------------

AC_INIT([xenaccess])
AC_CONFIG_SRCDIR(xenaccess/xa_memory.c)
AM_CONFIG_HEADER(config.h)

dnl -----------------------------------------------
dnl Package name and version number (user defined)
dnl -----------------------------------------------

LIBRARY_NAME=xenaccess

#release versioning
MAJOR_VERSION=0
MINOR_VERSION=5
MICRO_VERSION=1

dnl --------------------------------
dnl Package name and version number
dnl --------------------------------

PACKAGE=$LIBRARY_NAME
AC_SUBST(LIBRARY_NAME)

VERSION=$MAJOR_VERSION.$MINOR_VERSION.$MICRO_VERSION
RELEASE=$MAJOR_VERSION.$MINOR_VERSION
AC_SUBST(RELEASE)
AC_SUBST(VERSION)

VERSION=$VERSION

AM_INIT_AUTOMAKE($PACKAGE, $VERSION, no-define)

dnl -----------------------------------------------
dnl Check package options
dnl -----------------------------------------------
AC_ARG_ENABLE([xen],
      [AS_HELP_STRING([--disable-xen],
         [Support memory introspection with live Xen domains (default is yes)])],
      [enable_xen=$enableval],
      [enable_xen=yes])
AM_CONDITIONAL([XEN], [test x$enable_xen = xyes])

dnl -----------------------------------------------
dnl Checks for programs, libraries, etc.
dnl -----------------------------------------------

AC_PROG_CC
AM_PROG_LIBTOOL
AM_SANITY_CHECK

[if test "$enable_xen" = "yes"]
[then]
    AC_DEFINE([ENABLE_XEN], [1], [Define to 1 to enable Xen support.])
    AC_CHECK_LIB(xenstore, xs_read, [LIBS="-lxenstore $LIBS"], [LIBS="no"])
    [if test "$LIBS" = "no"]
    [then]
        [echo "xenstore library not found. Please install this library and"]
        [echo "run configure again before attemping to build XenAccess."]
        [exit 1]
    [fi]

    AC_CHECK_LIB(xenctrl, xc_interface_open, [LIBS="-lxenctrl $LIBS"], [LIBS="no"])
    [if test "$LIBS" = "no"]
    [then]
        [echo "xenctrl library not found. Please install this library and"]
        [echo "run configure again before attemping to build XenAccess."]
        [exit 1]
    [fi]

    AC_CHECK_FUNCS(xc_map_foreign_pages, AC_DEFINE([HAVE_MAP_FOREIGN], [], [Indicates existance of xc_map_foreign_pages]))

    AC_CHECK_TYPE(
        [vcpu_guest_context_any_t],
        AC_DEFINE([HAVE_CONTEXT_ANY], [1], [Checks existance of vcpu_guest_context_any_t to know how to check cpu context on this libxc version.]),
        [],
        [#include "xenctrl.h"])
[fi]

AC_CHECK_PROGS(YACC,bison yacc byacc,[no],[path = $PATH])
[if test "$YACC" = "no"]
[then]
    [echo "yacc not found in the search path. Please ensure that it is"]
    [echo "installed and its directory is included in the search path."]
    [echo "Then run configure again before attempting to build XenAccess."]
    [exit 1]
[else]
    [echo "Found yacc as $YACC."]
[fi]
AC_PROG_YACC

AC_CHECK_PROGS(LEX,lex flex ,[no],[path = $PATH])
[if test "$LEX" = "no"]
[then]
    [echo "lex not found in the search path. Please ensure that it is"]
    [echo "installed and its directory is included in the search path".]
    [echo "Then run configure again before attempting to build XenAccess."]
    [exit 1]
[else]
    [echo "Found lex as $LEX."]
[fi]
AC_PROG_LEX


dnl -----------------------------------------------
dnl Generates Makefile's, configuration files and scripts
dnl -----------------------------------------------

AC_CONFIG_FILES(Makefile \
                xenaccess.pc \
                xenaccess/Makefile \
                xenaccess/config/Makefile \
                examples/Makefile
)
AC_OUTPUT


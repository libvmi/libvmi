dnl --------------------------------
dnl Initialization macros.
dnl --------------------------------

AC_INIT([libvmi], [0.13.0])
AM_INIT_AUTOMAKE([subdir-objects])

LT_INIT

AC_CONFIG_SRCDIR(libvmi/core.c)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS(config.h)

AC_CANONICAL_HOST

LIBRARY_NAME=libvmi
MAJOR_VERSION=0
MINOR_VERSION=13
MICRO_VERSION=0
VERSION=$MAJOR_VERSION:$MINOR_VERSION:$MICRO_VERSION
RELEASE=$MAJOR_VERSION.$MINOR_VERSION

AC_SUBST(LIBRARY_NAME)
AC_SUBST(VERSION)
AC_SUBST(RELEASE)

AC_MSG_CHECKING([for supported architecture])
case "$host_cpu" in
i[[3456]]86|pentium)
    arch=i386
    AC_DEFINE([I386], 1, [Define for the i386 architecture.])
    ;;
x86?64*)
    arch=x86_64
    AC_DEFINE([X86_64], 1, [Define for the AMD x86-64 architecture.])
    ;;
arm*)
    arch=arm32
    AC_DEFINE([ARM32], 1, [Define for the ARM32 architecture.])
    ;;
aarch64*)
    arch=arm64
    AC_DEFINE([ARM64], 1, [Define for the ARM64 architecture.])
    ;;
esac
AC_MSG_RESULT($arch)

dnl -----------------------------------------------
dnl Helper function to check presence of a define
dnl -----------------------------------------------
AC_DEFUN([AC_CHECK_DEFINE],[dnl
    AC_CACHE_CHECK(for $1 in $2, ac_cv_define_$1,
        AC_EGREP_CPP([YES_IS_DEFINED], [
#include <$2>
#ifdef $1
YES_IS_DEFINED
#endif
        ], ac_cv_define_$1=yes, ac_cv_define_$1=no)
    )
    if test "$ac_cv_define_$1" = "yes" ; then
        AC_DEFINE([HAVE_$1],[],[Added by AC_CHECK_DEFINE])
        have_$1="yes"
    else
        have_$1="no"
    fi
])dnl

dnl -----------------------------------------------
dnl Check package options
dnl -----------------------------------------------
AC_ARG_ENABLE([xen],
      [AS_HELP_STRING([--disable-xen],
         [Support memory introspection with live Xen domains (default is yes)])],
      [enable_xen=$enableval],
      [enable_xen=yes])
AM_CONDITIONAL([WITH_XEN], [test x"$enable_xen" = xyes])

AC_ARG_WITH([xenstore],
      [AS_HELP_STRING([--without-xenstore],
         [Build LibVMI without Xenstore])],
      [with_xenstore=$withval],
      [with_xenstore=yes])
AM_CONDITIONAL([XENSTORE], [test x"$with_xenstore" = xyes])

AC_ARG_ENABLE([kvm],
      [AS_HELP_STRING([--disable-kvm],
         [Support memory introspection with live KVM VMs (default is yes)])],
      [enable_kvm=$enableval],
      [enable_kvm=yes])
AM_CONDITIONAL([WITH_KVM], [test x"$enable_kvm" = xyes])

AC_ARG_ENABLE([shm_snapshot],
      [AS_HELP_STRING([--disable-shm-snapshot],
         [Support shm-snapshot with KVM VMs (Xen is pending) (default is no)])],
      [enable_shm_snapshot=$enableval],
      [enable_shm_snapshot=no])
AM_CONDITIONAL([SHM], [test x"$enable_shm_snapshot" = xyes])

AC_ARG_ENABLE([file],
      [AS_HELP_STRING([--disable-file],
         [Support memory introspection with physical memory dumps in a file (default is yes)])],
      [enable_file=$enableval],
      [enable_file=yes])
AM_CONDITIONAL([WITH_FILE], [test x"$enable_file" = xyes])

AC_ARG_ENABLE([windows],
      [AS_HELP_STRING([--disable-windows],
         [Support introspecting Windows (XP - 8)])],
      [enable_windows=$enableval],
      [enable_windows=yes])
AM_CONDITIONAL([WINDOWS], [test x"$enable_windows" = xyes])

AC_ARG_ENABLE([linux],
      [AS_HELP_STRING([--disable-linux],
         [Support introspecting Linux])],
      [enable_linux=$enableval],
      [enable_linux=yes])
AM_CONDITIONAL([LINUX], [test x"$enable_linux" = xyes])

AC_ARG_ENABLE([freebsd],
      [AS_HELP_STRING([--disable-freebsd],
         [Support introspecting FreeBSD])],
      [enable_freebsd=$enableval],
      [enable_freebsd=yes])
AM_CONDITIONAL([FREEBSD], [test x"$enable_freebsd" = xyes])

AC_ARG_ENABLE([vmifs],
      [AS_HELP_STRING([--disable-vmifs],
         [Build VMIFS tool: maps memory to a file through FUSE])],
      [enable_vmifs=$enableval],
      [enable_vmifs=yes])
AM_CONDITIONAL([VMIFS], [test x"$enable_vmifs" = xyes])

AC_ARG_ENABLE([address_cache],
      [AS_HELP_STRING([--disable-address-cache],
         [Cache addresses (v2p, pid, etc)])],
      [enable_address_cache=$enableval],
      [enable_address_cache=yes])
AM_CONDITIONAL([ENABLE_ADDRESS_CACHE], [test x"$enable_address_cache" = "xyes"])

AC_ARG_ENABLE([page_cache],
      [AS_HELP_STRING([--disable-page-cache],
         [Cache pages])],
      [enable_page_cache=$enableval],
      [enable_page_cache=512])

AC_ARG_ENABLE([examples],
      [AS_HELP_STRING([--disable-examples],
         [Build LibVMI examples (default is yes)])],
      [enable_examples=$enableval],
      [enable_examples=yes])

AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug],
    [Enable strict compiler checks @<:@no@:>@])],
  [debug="$enableval"],
  [debug="no"])
AM_CONDITIONAL([DEBUG], [test x$debug = xyes])

AC_ARG_ENABLE([rekall_profiles],
  [AS_HELP_STRING([--enable-rekall-profiles],
    [Enable using Rekall's JSON profiles])],
  [rekall="$enableval"],
  [rekall="yes"])

AC_ARG_ENABLE([config-file],
  [AS_HELP_STRING([--disable-config-file],
    [Disable using LibVMI config files @<:@no@:>@])],
  [configfile="$enableval"],
  [configfile="yes"])
AM_CONDITIONAL([CONFIGFILE], [test x$configfile = xyes])

dnl -----------------------------------------------
dnl Checks for programs, libraries, etc.
dnl -----------------------------------------------

AC_PROG_CC
AM_PROG_CC_C_O
AM_SANITY_CHECK

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [have_check="yes"], [have_check="no"])
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.16],[],[AC_MSG_ERROR(GLib 2.16 or newer not found. Install missing package and re-run)])
AC_SUBST([GLIB_CFLAGS])
AC_SUBST([GLIB_LIBS])

[if test "$enable_xen" = "yes" || test "$enable_kvm" = "yes"]
[then]
    AC_CHECK_LIB(dl, dlopen, [],
        [AC_MSG_ERROR(No dl found. Install missing package or re-run with --disable-kvm --disable-xen)])
[fi]

[if test "$enable_xen" = "yes"]
[then]
    AC_CHECK_HEADERS([xenctrl.h xen/io/ring.h], [],
        [AC_MSG_ERROR([Required Xen headers not found. Install missing package or re-run with --disable-xen])])

    AC_CHECK_TYPE(
        [hvmmem_access_t],
        [AC_DEFINE([HAVE_HVMMEM_ACCESS_T], [1], [xen headers define hvmmem_access_t])],
        [],
        [#include <xenctrl.h> #include <xen/hvm/save.h>])

    AC_CHECK_TYPE(
        [xenmem_access_t],
        [AC_DEFINE([HAVE_XENMEM_ACCESS_T], [1], [xen headers define xenmem_access_t])],
        [],
        [#include <xenctrl.h> #include <xen/memory.h>])

    AC_DEFINE([ENABLE_XEN], [1], [Define to 1 to enable Xen support.])

    [if test "$with_xenstore" = "yes"]
    [then]
        AC_CHECK_HEADERS([xenstore.h xs.h])
        AC_DEFINE([HAVE_LIBXENSTORE], [1], [Define to 1 to enable Xenstore support.])
    [fi]
[fi]

[if test "$enable_kvm" = "yes"]
[then]
    AC_CHECK_LIB(m, ceil, [],
        [AC_MSG_ERROR(No libm found. Install missing package or re-run with --disable-kvm)])
    AC_CHECK_HEADER(libvirt/libvirt.h, [],
        [AC_MSG_ERROR([No libvirt headers found. Install missing package or re-run with --disable-kvm])])
    AC_DEFINE([ENABLE_KVM], [1], [Define to 1 to enable KVM support.])
    AC_CHECK_HEADER([qemu/libvmi_request.h],
        [AC_DEFINE([HAVE_LIBVMI_REQUEST], 1,
           [Define to 1 if you have <qemu/libvmi_request.h>.])],
        [])
    AC_CHECK_LIB(json-c, json_object_get_int64, [],
                     [AC_MSG_ERROR(["No working JSON-C library found (libjson-c-dev)."])])
    AC_CHECK_HEADER(json-c/json.h, [],
                     [AC_MSG_ERROR(["No working JSON-C library found (libjson-c-dev)."])])
[fi]

[if test "$enable_shm_snapshot" = "yes"]
[then]
    AC_CHECK_LIB(rt, shm_open, [],
        [AC_MSG_ERROR(No shm_open in rt. Install missing package or re-run with --disable-shm-snapshot)])
    AC_DEFINE([ENABLE_SHM_SNAPSHOT], [1], [Define to 1 to enable shm-snapshot support.])
[fi]

[if test "$enable_file" = "yes"]
[then]
    AC_DEFINE([ENABLE_FILE], [1], [Define to 1 to enable file support.])
[fi]

[if test "$enable_windows" = "yes"]
[then]
    AC_DEFINE([ENABLE_WINDOWS], [1], [Define to 1 to Windows support.])
[fi]

[if test "$enable_linux" = "yes"]
[then]
    AC_DEFINE([ENABLE_LINUX], [1], [Define to 1 to Linux support.])
[fi]
[if test "$enable_freebsd" = "yes"]
[then]
    AC_DEFINE([ENABLE_FREEBSD], [1], [Define to 1 to FreeBSD support.])
[fi]

have_vmifs='no'
vmifs_space='       '
[if test "$enable_vmifs" = "yes"]
[then]
    PKG_CHECK_MODULES([FUSE], [fuse >= 2.2], [missing="no"], [missing="yes"])
    [if test x"$missing" = "xyes"]
    [then]
        AC_DEFINE([ENABLE_VMIFS], [0], [Define to 1 to build VMIFS.])
        have_vmifs='FUSE library missing (libfuse-dev)'
        enable_vmifs='no'
	vmifs_space=' '
    [else]
        AC_DEFINE([ENABLE_VMIFS], [1], [Define to 1 to build VMIFS.])
        AC_SUBST([FUSE_CFLAGS])
        AC_SUBST([FUSE_LIBS])
        vmifs_dir="tools/vmifs"
        AC_SUBST(vmifs_dir)
        have_vmifs='yes'
        vmifs_space='      '
        AC_CONFIG_FILES(tools/vmifs/Makefile)
    [fi]
[fi]

[if test "$configfile" = "yes"]
[then]
    AC_CHECK_PROGS(YACC, bison yacc byacc, [no], [path = $PATH])
    [if test "$YACC" = "no"]
    [then]
        [echo "yacc not found in the search path. Please ensure that it is"]
        [echo "installed and its directory is included in the search path."]
        [echo "Then run configure again before attempting to build LibVMI."]
        [exit 1]
    [else]
        [echo "Found yacc as $YACC."]
    [fi]
    AC_PROG_YACC

    AC_CHECK_PROGS(LEX, lex flex , [no], [path = $PATH])
    [if test "$LEX" = "no"]
    [then]
        [echo "lex not found in the search path. Please ensure that it is"]
        [echo "installed and its directory is included in the search path".]
        [echo "Then run configure again before attempting to build LibVMI."]
        [exit 1]
    [else]
        [echo "Found lex as $LEX."]
    [fi]
    AC_PROG_LEX
    AC_DEFINE([ENABLE_CONFIGFILE], [1], [Enable libvmi.conf])
[fi]

missing='no'
[if test "$rekall" = "yes"]
[then]
    AC_CHECK_LIB(json-c, json_object_get_int64,, [missing="yes"])
    [if test x"$missing" = "xno"]
    [then]
            AC_CHECK_HEADERS([json-c/json.h])
            AC_DEFINE([REKALL_PROFILES], [1], [Defined to 1 when working JSON-C library was found to parse Rekall profiles.])
    [else]
        rekall='Disabled, missing libjson-c-dev.'
        [echo "No working JSON-C library found (libjson-c-dev), Rekall system profiles won't be supported."]
    [fi]
[fi]
AM_CONDITIONAL([REKALL_PROFILES], [test x"$rekall" = xyes])

[if test "$enable_address_cache" = "yes"]
[then]
        AC_DEFINE([ENABLE_ADDRESS_CACHE], [1], [Enable or disable the address cache (v2p, pid, etc)])
[fi]

[if test x"$enable_page_cache" != "xno"]
[then]
        AC_DEFINE([ENABLE_PAGE_CACHE], [1], [Enable or disable the page cache])
        AC_DEFINE_UNQUOTED([MAX_PAGE_CACHE_SIZE], [$enable_page_cache], [Max number of pages held in page cache])
[fi]

dnl -----------------------------------------------
dnl Generates Makefile's, configuration files and scripts
dnl -----------------------------------------------

AC_CONFIG_FILES(Makefile \
                libvmi.pc \
                libvmi/Makefile \
)

examples_space='     '
[if test "$enable_examples" = "yes"]
[then]
    AC_CONFIG_FILES(examples/Makefile)
    examples_space='    '
    examples_dir='examples/'
    AC_SUBST([examples_dir])
[fi]

[if test "$have_check" = "yes"]
[then]
    AC_CONFIG_FILES(tests/Makefile)
    test_dir="tests"
    AC_SUBST([test_dir])
[fi]

[if test "$configfile" = "yes"]
[then]
    AC_CONFIG_FILES(libvmi/config/Makefile)
    config_dir="libvmi/config"
    AC_SUBST([config_dir])
[fi]

AC_OUTPUT

dnl -----------------------------------------------
dnl Print current configuration out for user
dnl -----------------------------------------------

AC_MSG_RESULT([-------------------------------------------------------------------------------
LibVMI is configured as follows. Please verify that this configuration
matches your expectations.

Host system type: $host
Build system type: $build
Installation prefix: $prefix

Feature         | Option
----------------|---------------------------
Xen Support     | --enable-xen=$enable_xen
KVM Support     | --enable-kvm=$enable_kvm
File Support    | --enable-file=$enable_file
Shm-snapshot    | --enable-shm-snapshot=$enable_shm_snapshot
Rekall profiles | --enable-rekall-profiles=$rekall
----------------|---------------------------

OS              | Option
----------------|---------------------------
Windows         | --enable-windows=$enable_windows
Linux           | --enable-linux=$enable_linux
FreeBSD         | --enable-freebsd=$enable_freebsd

Tools           | Option                    | Reason
----------------|---------------------------|----------------------------
Examples        | --enable-examples=$enable_examples
VMIFS           | --enable-vmifs=$enable_vmifs$vmifs_space  | $have_vmifs

If everything is correct, you can now run 'make' and (optionally)
'make install'.  Otherwise, you can run './configure' again.
])

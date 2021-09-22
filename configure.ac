dnl --------------------------------
dnl Initialization macros.
dnl --------------------------------

AC_PREREQ([2.60])
AC_INIT([libvmi], [0.15.0])
AM_INIT_AUTOMAKE([1.10 no-define foreign subdir-objects])

LT_INIT

AC_CONFIG_SRCDIR(libvmi/core.c)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS(config.h)

AC_CANONICAL_HOST

LIBRARY_NAME=libvmi
MAJOR_VERSION=0
MINOR_VERSION=15
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
dnl Check package options
dnl -----------------------------------------------
AC_ARG_ENABLE([xen],
      [AS_HELP_STRING([--disable-xen],
         [Disable support for memory introspection with live Xen domains @<:@no@:>@])],
      [enable_xen=$enableval],
      [enable_xen=yes])
AM_CONDITIONAL([WITH_XEN], [test x"$enable_xen" = xyes])

AC_ARG_WITH([xenstore],
      [AS_HELP_STRING([--without-xenstore],
         [Build LibVMI without Xenstore @<:@no@:>@])],
      [with_xenstore=$withval],
      [with_xenstore=yes])
AM_CONDITIONAL([XENSTORE], [test x"$with_xenstore" = xyes])

AC_ARG_ENABLE([kvm],
      [AS_HELP_STRING([--disable-kvm],
         [Disable support for memory introspection with live KVM VMs @<:@no@:>@])],
      [enable_kvm=$enableval],
      [enable_kvm=yes])
AM_CONDITIONAL([WITH_KVM], [test x"$enable_kvm" = xyes])

AC_ARG_ENABLE([kvm_legacy],
      [AS_HELP_STRING([--disable-kvm-legacy],
         [Enable support for legacy KVM driver @<:@no@:>@])],
      [enable_kvm_legacy=$enableval],
      [enable_kvm_legacy=no])
AM_CONDITIONAL([WITH_KVM_LEGACY], [test x"$enable_kvm_legacy" = xyes])

AC_ARG_ENABLE([bareflank],
      [AS_HELP_STRING([--disable-bareflank],
         [Support memory introspection with live Bareflank VMs (default is yes)])],
      [enable_bareflank=$enableval],
      [enable_bareflank=yes])
AM_CONDITIONAL([WITH_BAREFLANK], [test x"$enable_bareflank" = xyes && test "$arch" = "x86_64"])

AC_ARG_ENABLE([file],
      [AS_HELP_STRING([--disable-file],
         [Disable support for memory introspection with physical memory dumps in a file @<:@no@:>@])],
      [enable_file=$enableval],
      [enable_file=yes])
AM_CONDITIONAL([WITH_FILE], [test x"$enable_file" = xyes])

AC_ARG_ENABLE([windows],
      [AS_HELP_STRING([--disable-windows],
         [Disable support for introspecting Windows (XP - 10) @<:@no@:>@])],
      [enable_windows=$enableval],
      [enable_windows=yes])
AM_CONDITIONAL([WINDOWS], [test x"$enable_windows" = xyes])

AC_ARG_ENABLE([linux],
      [AS_HELP_STRING([--disable-linux],
         [Disable support for introspecting Linux @<:@no@:>@])],
      [enable_linux=$enableval],
      [enable_linux=yes])
AM_CONDITIONAL([LINUX], [test x"$enable_linux" = xyes])

AC_ARG_ENABLE([freebsd],
      [AS_HELP_STRING([--disable-freebsd],
         [Disable support for introspecting FreeBSD @<:@no@:>@])],
      [enable_freebsd=$enableval],
      [enable_freebsd=yes])
AM_CONDITIONAL([FREEBSD], [test x"$enable_freebsd" = xyes])

AC_ARG_ENABLE([vmifs],
      [AS_HELP_STRING([--disable-vmifs],
         [Disable building VMIFS tool: maps memory to a file through FUSE @<:@no@:>@])],
      [enable_vmifs=$enableval],
      [enable_vmifs=yes])

AC_ARG_ENABLE([address-cache],
      [AS_HELP_STRING([--disable-address-cache],
         [Disable caching addresses (v2p, pid, etc) @<:@no@:>@])],
      [enable_address_cache=$enableval],
      [enable_address_cache=yes])
AM_CONDITIONAL([ENABLE_ADDRESS_CACHE], [test x"$enable_address_cache" = "xyes"])

AC_ARG_ENABLE([page-cache],
      [AS_HELP_STRING([--disable-page-cache],
         [Disable caching pages @<:@no@:>@])],
      [enable_page_cache=$enableval],
      [enable_page_cache=512])
AM_CONDITIONAL([ENABLE_PAGE_CACHE], [test x"$enable_page_cache" = "xyes"])

AC_ARG_ENABLE([rekall-profiles],
      [AS_HELP_STRING([--disable-rekall-profiles],
         [Disable support for Rekall's JSON profiles @<:@no@:>@])],
      [rekall="$enableval"],
      [rekall="yes"])

AC_ARG_ENABLE([volatility-ist],
      [AS_HELP_STRING([--disable-volatility-ist],
         [Disable support for Volatility's JSON intermediate symbol table @<:@no@:>@])],
      [volatility_ist="$enableval"],
      [volatility_ist="yes"])

AC_ARG_ENABLE([config-file],
      [AS_HELP_STRING([--disable-config-file],
         [Disable using LibVMI config files @<:@no@:>@])],
      [configfile="$enableval"],
      [configfile="yes"])
AM_CONDITIONAL([ENABLE_CONFIGFILE], [test x$configfile = xyes])

AC_ARG_ENABLE([safety-checks],
      [AS_HELP_STRING([--disable-safety-checks],
         [Disable API safety checks @<:@no@:>@])],
      [enable_safety_checks=$enableval],
      [enable_safety_checks=yes])
AM_CONDITIONAL([ENABLE_SAFETY_CHECKS], [test x"$enable_safety_checks" = "xyes"])

AC_ARG_ENABLE([vmi-debug],
      [AS_HELP_STRING([--enable-vmi-debug],
         [Enable VMI debug prints when LIBVMI_DEBUG environment variable is set @<:@no@:>@])],
      [enable_vmi_debug=$enableval],
      [enable_vmi_debug=no])
AM_CONDITIONAL([VMI_DEBUG], [test x"$enable_vmi_debug" = "xyes"])
AM_CONDITIONAL([ENV_DEBUG], [test x"$enable_vmi_debug" = "xyes"])

AC_ARG_ENABLE([examples],
      [AS_HELP_STRING([--disable-examples],
         [Disable building LibVMI examples @<:@yes@:>@])],
      [enable_examples=$enableval],
      [enable_examples=yes])
AM_CONDITIONAL([EXAMPLES], [test x"$enable_examples" = "xyes"])

AC_ARG_ENABLE([debug],
      [AS_HELP_STRING([--enable-debug],
         [Enable strict compiler checks @<:@no@:>@])],
      [debug="$enableval"],
      [debug="no"])
AM_CONDITIONAL([DEBUG], [test x$debug = xyes])

AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--enable-hardening],
    [Enable compiler and linker options to frustrate memory corruption exploits @<:@yes@:>@])],
  [hardening="$enableval"],
  [hardening="yes"])
AM_CONDITIONAL([HARDENING], [test x$hardening = xyes])

dnl -----------------------------------------------
dnl Checks for programs, libraries, etc.
dnl -----------------------------------------------

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CC_C99
AM_SANITY_CHECK
AM_PROG_AS

#####################################################
# AUTOHARDEN START
# We want to check for compiler flag support, but there is no way to make
# clang's "argument unused" warning fatal.  So we invoke the compiler through a
# wrapper script that greps for this message.

saved_CC="$CC"
saved_LD="$LD"
flag_wrap="$srcdir/wrap-compiler-for-flag-check"
CC="$flag_wrap $CC"
LD="$flag_wrap $LD"

# We use the same hardening flags for C and C++.  We must check that each flag
# is supported by both compilers.
AC_DEFUN([check_cc_flag],
  [AC_LANG_PUSH(C)
  AX_CHECK_COMPILE_FLAG([$1], [$2], [$3], [-Werror $4])
  AC_LANG_POP(C)])
AC_DEFUN([check_link_flag],
 [AX_CHECK_LINK_FLAG([$1], [$2], [$3], [-Werror $4])])

HARDEN_CFLAGS=""
HARDEN_LDFLAGS=""
AS_IF([test x"$hardening" != x"no"], [
  check_cc_flag([-fno-strict-overflow], [HARDEN_CFLAGS="$HARDEN_CFLAGS -fno-strict-overflow"])

  # This one will likely succeed, even on platforms where it does nothing.
  check_cc_flag([-D_FORTIFY_SOURCE=2 -O2], [HARDEN_CFLAGS="$HARDEN_CFLAGS -D_FORTIFY_SOURCE=2 -O2"])

  check_cc_flag([-fstack-protector-all],
   [check_link_flag([-fstack-protector-all],
     [HARDEN_CFLAGS="$HARDEN_CFLAGS -fstack-protector-all"
      check_cc_flag([-Wstack-protector], [HARDEN_CFLAGS="$HARDEN_CFLAGS -Wstack-protector"],
        [], [-fstack-protector-all])
      check_cc_flag([--param ssp-buffer-size=1], [HARDEN_CFLAGS="$HARDEN_CFLAGS --param ssp-buffer-size=1"],
        [], [-fstack-protector-all])])])

  # At the link step, we might want -pie (GCC) or -Wl,-pie (Clang on OS X)
  #
  # The linker checks also compile code, so we need to include -fPIE as well.
  check_cc_flag([-fPIE],
   [check_link_flag([-fPIE -pie],
     [HARDEN_CFLAGS="$HARDEN_CFLAGS -fPIE"
      HARDEN_LDFLAGS="$HARDEN_LDFLAGS -pie"],
     [check_link_flag([-fPIE -Wl,-pie],
       [HARDEN_CFLAGS="$HARDEN_CFLAGS -fPIE"
        HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-pie"])])])

  check_link_flag([-Wl,-z,noexecstack],
   [HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-z,noexecstack"])
  check_link_flag([-Wl,-z,relro],
   [HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-z,relro"])
  check_link_flag([-Wl,-z,now],
   [HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-z,now"])
])

AC_SUBST([HARDEN_CFLAGS])
AC_SUBST([HARDEN_LDFLAGS])

# End of flag tests.
CC="$saved_CC"
LD="$saved_LD"
# AUTOHARDEN END
#####################################################

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [have_check="yes"], [have_check="no"])
AM_CONDITIONAL([MAKE_TESTS], [test x$have_check = xyes])

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.16],[],[AC_MSG_ERROR(GLib 2.16 or newer not found. Install missing package and re-run)])
PKG_CHECK_MODULES([JSONC], [json-c], [have_jsonc='yes'], [have_jsonc='no'])
AC_CHECK_LIB(json-c, json_object_get_uint64, [AC_DEFINE([JSONC_UINT64_SUPPORT], [1], [json-c supports unsigned 64-bit values])], [])

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

    AC_DEFINE([ENABLE_XEN], [1], [Define to 1 to enable Xen support.])

    [if test "$with_xenstore" = "yes"]
    [then]
        AC_CHECK_HEADERS([xenstore.h xs.h])
        AC_DEFINE([HAVE_LIBXENSTORE], [1], [Define to 1 to enable Xenstore support.])
    [fi]
[fi]

[if test "$enable_kvm" = "yes"]
[then]
    [if test "$have_jsonc" = "no"]
    [then]
        AC_MSG_ERROR(No json-c library found. Install missing package or re-run with --disable-kvm)
    [fi]
    AC_CHECK_LIB(m, ceil, [],
        [AC_MSG_ERROR(No libm found. Install missing package or re-run with --disable-kvm)])
    AC_CHECK_HEADER(libvirt/libvirt.h, [],
        [AC_MSG_ERROR([No libvirt headers found. Install missing package or re-run with --disable-kvm])])
    AC_DEFINE([ENABLE_KVM], [1], [Define to 1 to enable KVM support.])
    [if test "$enable_kvm_legacy" = "yes"]
    [then]
        AC_CHECK_LIB(json-c, json_object_get_int64, [],
                         [AC_MSG_ERROR(["No working JSON-C library found (libjson-c-dev)."])])
        AC_CHECK_HEADER(json-c/json.h, [],
                         [AC_MSG_ERROR(["No working JSON-C library found (libjson-c-dev)."])])
        AC_CHECK_HEADER([qemu/libvmi_request.h],
        [AC_DEFINE([HAVE_LIBVMI_REQUEST], 1,
           [Define to 1 if you have <qemu/libvmi_request.h>.])],
        [])
        AC_DEFINE([ENABLE_KVM_LEGACY], [1],
                  [Define to 1 to enable legacy KVM driver support.])
    [else]
        PKG_CHECK_MODULES([LIBKVMI], [libkvmi], [],
            [AC_MSG_ERROR([No libkvmi headers found. Install the library or
             enable the legacy KVM driver with --enable-kvm-legacy])])
    [fi]
[fi]

[if test "$enable_file" = "yes"]
[then]
    AC_DEFINE([ENABLE_FILE], [1], [Define to 1 to enable file support.])
[fi]

[if test "$enable_bareflank" = "yes" && test "$arch" = "x86_64"]
[then]
    [if test "$have_jsonc" = "no"]
    [then]
        AC_MSG_ERROR(No json-c library found. Install missing package or re-run with --disable-bareflank)
    [fi]
    AC_DEFINE([ENABLE_BAREFLANK], [1], [Define to 1 to enable Bareflank support.])
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

have_vmifs='yes'
[if test "$enable_vmifs" = "yes"]
[then]
    PKG_CHECK_MODULES([FUSE], [fuse >= 2.2], [missing="no"], [missing="yes"])
    [if test x"$missing" = "xyes"]
    [then]
        AC_DEFINE([ENABLE_VMIFS], [0], [Define to 1 to build VMIFS.])
        enable_vmifs='no'
    [else]
        AC_DEFINE([ENABLE_VMIFS], [1], [Define to 1 to build VMIFS.])
        AC_SUBST([FUSE_CFLAGS])
        AC_SUBST([FUSE_LIBS])
    [fi]
[fi]
AM_CONDITIONAL([VMIFS], [test x"$enable_vmifs" = xyes])

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

[if test "$rekall" = "yes" || test "$volatility_ist" = "yes"]
[then]
    [if test "$have_jsonc" = "no"]
    [then]
        AC_MSG_ERROR(No json-c library found. Install missing package or re-run with --disable-rekall-profiles --disable-volatility-ist)
    [fi]
    AC_DEFINE([ENABLE_JSON_PROFILES], [1], [Defined to 1 when support to JSON profiles is available])
    AM_CONDITIONAL([ENABLE_JSON_PROFILES], [test "true" = "true"])
    [if test "$rekall" = "yes"]
    [then]
        AC_DEFINE([REKALL_PROFILES], [1], [Defined to 1 when support to Rekall profiles should be compiled])
    [fi]
    [if test "$volatility_ist" = "yes"]
    [then]
        AC_DEFINE([VOLATILITY_IST], [1], [Defined to 1 when support to Volatility IST should be compiled])
    [fi]
[else]
    AM_CONDITIONAL([ENABLE_JSON_PROFILES], [test "true" = "false"])
[fi]
AM_CONDITIONAL([ENABLE_REKALL_PROFILES], [test x"$rekall" = "xyes"])
AM_CONDITIONAL([ENABLE_VOLATILITY_IST], [test x"$volatility_ist" = "xyes"])

[if test x"$enable_address_cache" = "xyes"]
[then]
        AC_DEFINE([ENABLE_ADDRESS_CACHE], [1], [Enable or disable the address cache (v2p, pid, etc)])
[fi]

[if test x"$enable_page_cache" != "xno"]
[then]
        AC_DEFINE([ENABLE_PAGE_CACHE], [1], [Enable or disable the page cache])
        AC_DEFINE_UNQUOTED([MAX_PAGE_CACHE_SIZE], [$enable_page_cache], [Max number of pages held in page cache])
[fi]

[if test x"$enable_safety_checks" = "xyes"]
[then]
        AC_DEFINE([ENABLE_SAFETY_CHECKS], [1], [Enable API safety checks])
[fi]

[if test x"$enable_vmi_debug" = "xyes"]
[then]
        AC_DEFINE([VMI_DEBUG], [__VMI_DEBUG_ALL], [Enable LibVMI debug prints])
        AC_DEFINE([ENV_DEBUG], [1], [Enable debug prints only when LIBVMI_DEBUG environment variable is set])
[fi]

dnl -----------------------------------------------
dnl Generates Makefile's, configuration files and scripts
dnl -----------------------------------------------

AC_CONFIG_FILES(Makefile libvmi.pc:libvmi.pc.autotools.in)
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

Hypervisor              | Option
------------------------|---------------------------
Xen Support             | --enable-xen=$enable_xen
KVM Support             | --enable-kvm=$enable_kvm
Legacy KVM Driver       | --enable-kvm-legacy=$enable_kvm_legacy
File Support            | --enable-file=$enable_file
Bareflank               | --enable-bareflank=$enable_bareflank
------------------------|---------------------------

OS                      | Option
------------------------|---------------------------
Windows                 | --enable-windows=$enable_windows
Linux                   | --enable-linux=$enable_linux
FreeBSD                 | --enable-freebsd=$enable_freebsd
------------------------|---------------------------

Configuration           | Option
------------------------|---------------------------
libvmi.conf             | --enable-config-file=$configfile
Rekall profiles         | --enable-rekall-profiles=$rekall
Volatility IST          | --enable-volatility-ist=$volatility_ist
------------------------|---------------------------

Tools                   | Option
------------------------|---------------------------
Examples                | --enable-examples=$enable_examples
VMIFS                   | --enable-vmifs=$enable_vmifs

If everything is correct, you can now run 'make' and (optionally)
'make install'.  Otherwise, you can run './configure' again.
])

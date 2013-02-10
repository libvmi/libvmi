dnl --------------------------------
dnl Initialization macros.
dnl --------------------------------

AC_INIT([libvmi], [0.9.0])
AM_INIT_AUTOMAKE([subdir-objects])

AC_CONFIG_SRCDIR(libvmi/core.c)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS(config.h)

LIBRARY_NAME=libvmi
MAJOR_VERSION=0
MINOR_VERSION=9
MICRO_VERSION=0
VERSION=$MAJOR_VERSION.$MINOR_VERSION.$MICRO_VERSION
RELEASE=$MAJOR_VERSION.$MINOR_VERSION

AC_SUBST(LIBRARY_NAME)
AC_SUBST(VERSION)
AC_SUBST(RELEASE)

dnl -----------------------------------------------
dnl Check package options
dnl -----------------------------------------------
AC_ARG_ENABLE([xen],
      [AS_HELP_STRING([--disable-xen],
         [Support memory introspection with live Xen domains (default is yes)])],
      [enable_xen=$enableval],
      [enable_xen=yes])
AM_CONDITIONAL([XEN], [test x$enable_xen = xyes])

AC_ARG_ENABLE([kvm],
      [AS_HELP_STRING([--disable-kvm],
         [Support memory introspection with live KVM VMs (default is yes)])],
      [enable_kvm=$enableval],
      [enable_kvm=yes])
AM_CONDITIONAL([KVM], [test x$enable_kvm = xyes])

AC_ARG_ENABLE([file],
      [AS_HELP_STRING([--disable-file],
         [Support memory introspection with physical memory dumps in a file (default is yes)])],
      [enable_file=$enableval],
      [enable_file=yes])
AM_CONDITIONAL([FILE], [test x$enable_file = xyes])

AC_ARG_ENABLE([vmifs],
      [AS_HELP_STRING([--disable-vmifs],
         [Build VMIFS tool: maps memory to a file through FUSE])],
      [enable_vmifs=$enableval],
      [enable_vmifs=yes])
AM_CONDITIONAL([VMIFS], [test x$enable_vmifs = xyes])

dnl -----------------------------------------------
dnl Checks for programs, libraries, etc.
dnl -----------------------------------------------

AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_LIBTOOL
AM_SANITY_CHECK

have_xen='no'
xen_space=' '
[if test "$enable_xen" = "yes"]
[then]
    xen_space=''
    AC_CHECK_LIB(xenstore, xs_read, [], [missing="yes"])
    [if test "$missing" = "yes"]
    [then]
        AC_DEFINE([ENABLE_XEN], [0], [Define to 1 to enable Xen support.])
        missing='no'
        enable_xen='no'
        xen_space=' '
        have_xen='missing xenstore'
    [else]
        AC_CHECK_LIB(xenctrl, xc_interface_open, [], [missing="yes"])
        [if test "$missing" = "yes"]
        [then]
            AC_DEFINE([ENABLE_XEN], [0], [Define to 1 to enable Xen support.])
            missing='no'
            enable_xen='no'
            xen_space=' '
            have_xen='missing xenctrl'
        [else]
            AC_DEFINE([ENABLE_XEN], [1], [Define to 1 to enable Xen support.])
            have_xen='yes'

            AC_CHECK_HEADERS([xenstore.h])
            AC_CHECK_LIB(xenctrl, [xc_mem_event_enable], [AC_DEFINE(XENEVENT41, 1, "Xen memory event 4.1 style")])
            AC_CHECK_LIB(xenctrl, [xc_mem_access_enable], [AC_DEFINE(XENEVENT42, 1, "Xen memory event 4.2 style")])
        [fi]
    [fi]

    AC_CHECK_TYPE(
        [vcpu_guest_context_any_t],
        AC_DEFINE([HAVE_CONTEXT_ANY], [1], [Checks existance of vcpu_guest_context_any_t to know how to check cpu context on this libxc version.]),
        [],
        [#include "xenctrl.h"])
[fi]

have_kvm='no'
kvm_space=' '
[if test "$enable_kvm" = "yes"]
[then]
    AC_PATH_PROG(GREP, grep)
    [if test "x$GREP" = "x"]
    [then]
        AC_DEFINE([ENABLE_KVM], [0], [Define to 1 to enable KVM support.])
        missing='no'
        enable_kvm='no'
        kvm_space=' '
        have_kvm='grep missing'
    [fi]

    AC_PATH_PROG(LSMOD, lsmod)
    [if test "x$LSMOD" = "x"]
    [then]
        AC_DEFINE([ENABLE_KVM], [0], [Define to 1 to enable KVM support.])
        missing='no'
        enable_kvm='no'
        kvm_space=' '
        have_kvm='lsmod missing'
    [fi]
    
    [if test "x$LSMOD" != "x" && test "x$GREP" != "x"]
    [then]
        KVM_PRESENT=$($LSMOD | $GREP kvm)
        [if test "x$KVM_PRESENT" != "x"]
        [then]
            AC_CHECK_LIB(virt, virConnectOpen, [], [missing="yes"])
            [if test "$missing" = "yes"]
            [then]
                AC_DEFINE([ENABLE_KVM], [0], [Define to 1 to enable KVM support.])
                missing='no'
                enable_kvm='no'
                kvm_space=' '
                have_kvm='libvirt missing'
            [else]
                AC_DEFINE([ENABLE_KVM], [1], [Define to 1 to enable KVM support.])
                have_kvm='yes'
                kvm_space=''
            [fi]
        [else]
            AC_DEFINE([ENABLE_KVM], [0], [Define to 1 to enable KVM support.])
            missing='no'
            enable_kvm='no'
            kvm_space=' '
            have_kvm='kernel module is not loaded'
        [fi]
    [fi]
[fi]

have_file='no'
file_space=' '
[if test "$enable_file" = "yes"]
[then]
    AC_DEFINE([ENABLE_FILE], [1], [Define to 1 to enable file support.])
    file_space=''
    have_file='yes'
[fi]

have_vmifs='no'
vmifs_space=' '
[if test "$enable_vmifs" = "yes"]
[then]
    vmifs_space=''
    PKG_CHECK_MODULES([FUSE], [fuse >= 2.2], [], [missing="yes"])
    [if test "$missing" = "yes"]
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
        AC_CONFIG_FILES(tools/vmifs/Makefile)
    [fi]
[fi]

AC_CHECK_PROGS(YACC,bison yacc byacc,[no],[path = $PATH])
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

AC_CHECK_PROGS(LEX,lex flex ,[no],[path = $PATH])
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

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.16])
AC_SUBST([GLIB_CFLAGS])
AC_SUBST([GLIB_LIBS])

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

dnl -----------------------------------------------
dnl Generates Makefile's, configuration files and scripts
dnl -----------------------------------------------

AC_CONFIG_FILES(Makefile \
                libvmi.pc \
                libvmi/Makefile \
                libvmi/config/Makefile \
                examples/Makefile \
                tests/Makefile
)

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

Feature      | Option             | Reason
-------------|--------------------|-----------------------
Xen Support  | --enable-xen=$enable_xen$xen_space   | $have_xen
KVM Support  | --enable-kvm=$enable_kvm$kvm_space   | $have_kvm
File Support | --enable-file=$enable_file$file_space  | $have_file
-------------|--------------------|-----------------------

Tools        | Option             | Reason
-------------|--------------------|-----------------------
VMIFS        | --enable-vmifs=$enable_vmifs$vmifs_space | $have_vmifs
 
If everything is correct, you can now run 'make' and (optionally)
'make install'.  Otherwise, you can run './configure' again.
])

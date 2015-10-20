dnl --------------------------------
dnl Initialization macros.
dnl --------------------------------

AC_INIT([libvmi], [0.11.0])
AM_INIT_AUTOMAKE([subdir-objects])

AC_CONFIG_SRCDIR(libvmi/core.c)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS(config.h)

AC_CANONICAL_HOST

LIBRARY_NAME=libvmi
MAJOR_VERSION=0
MINOR_VERSION=11
MICRO_VERSION=0
VERSION=$MAJOR_VERSION.$MINOR_VERSION.$MICRO_VERSION
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
    arch=arm
    AC_DEFINE([ARM], 1, [Define for the ARM architecture.])
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
AM_CONDITIONAL([XEN], [test x"$enable_xen" = xyes])

AC_ARG_ENABLE([xen_events],
      [AS_HELP_STRING([--enable-xen-events],
         [Support use of Xen memory events (default is no)])],
      [enable_xen_events=$enableval],
      [enable_xen_events=no])
AM_CONDITIONAL([XEN_EVENTS], [test x"$enable_xen_events" = xyes])

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
AM_CONDITIONAL([KVM], [test x"$enable_kvm" = xyes])

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
AM_CONDITIONAL([FILE], [test x"$enable_file" = xyes])

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

dnl -----------------------------------------------
dnl Checks for programs, libraries, etc.
dnl -----------------------------------------------

AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_LIBTOOL
AM_SANITY_CHECK

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [have_check="yes"], [have_check="no"])
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.16])
AC_SUBST([GLIB_CFLAGS])
AC_SUBST([GLIB_LIBS])
AC_CHECK_LIB(m, ceil)

have_xen='no'
xen_space='      '
have_xen_events='no'
have_xen_events_legacy='no'
xen_event_space=' '
[if test "$enable_xen" = "yes"]
[then]

    [if test "$with_xenstore" = "yes"]
    [then]
        AC_CHECK_LIB(xenstore, xs_read, [], [missing="yes"])
        AC_CHECK_HEADERS([xenstore.h])
        AC_CHECK_HEADERS([xs.h])
    [fi]

    [if test "$with_xenstore" = "yes" -a "$missing" = "yes"]
    [then]
        AC_DEFINE([ENABLE_XEN], [0], [Define to 1 to enable Xen support.])
        missing='no'
        enable_xen='no'
        have_xen='missing xenstore'
    [else]
        AC_CHECK_LIB(xenctrl, xc_interface_open, [], [missing="yes"])
        [if test "$missing" = "yes"]
        [then]
            AC_DEFINE([ENABLE_XEN], [0], [Define to 1 to enable Xen support.])
            missing='no'
            enable_xen='no'
            have_xen='missing xenctrl'
        [else]
            AC_DEFINE([ENABLE_XEN], [1], [Define to 1 to enable Xen support.])
            have_xen='yes'
            xen_space='     '

            [if test "$enable_xen_events" = "yes"]
            [then]

                have_xc_mem_event_enable='no'
                have_xc_mem_access_enable='no'
                have_xc_monitor_enable='no'
                have_hvmmem_access_t='no'
                have_xenmem_access_t='no'

                # Check for xen events capability (only relevant if Xen is enabled).
                AC_CHECK_LIB(xenctrl,
                    [xc_monitor_enable],
                    [
                        have_xc_monitor_enable='yes'
                        AC_DEFINE([HAVE_XC_MONITOR_ENABLE], [1], "xenctrl has xc_monitor_enable")
                    ]
                )

                [if test "$have_xc_monitor_enable" = "no"]
                [then]
                    AC_CHECK_LIB(xenctrl,
                        [xc_mem_event_enable],
                        [
                            have_xc_mem_event_enable='yes'
                            AC_DEFINE([HAVE_XC_MEM_EVENT_ENABLE], [1], "xenctrl has xc_mem_event_enable")
                        ]
                    )
                [fi]

                [if test "$have_xc_monitor_enable" = "no" && test "$have_xc_mem_event_enable" = "no"]
                [then]
                    AC_CHECK_LIB(xenctrl,
                        [xc_mem_access_enable],
                        [
                            have_xc_mem_access_enable='yes'
                            AC_DEFINE([HAVE_XC_MEM_ACCESS_ENABLE], [1], "xenctrl has xc_mem_access_enable")
                        ]
                    )
                [fi]


                # MSR events are only available in Xen 4.3+
                [if test "$have_xc_monitor_enable" = "no"]
                [then]
                    AC_CHECK_HEADERS([xen/mem_event.h],
                        [
                            AC_DEFINE([HAVE_MEM_EVENT_H], [1], "Xen provides mem_event.h")
                            AC_CHECK_DEFINE(MEM_EVENT_REASON_MSR, xen/mem_event.h)
                        ]
                    )
                [else]
                    AC_CHECK_HEADERS([xen/vm_event.h],
                        [
                            AC_DEFINE([HAVE_VM_EVENT_H], [1], "Xen provides vm_event.h")
                            AC_CHECK_DEFINE(VM_EVENT_INTERFACE_VERSION, xen/vm_event.h)
                        ]
                    )
                [fi]

                AC_CHECK_DEFINE(XENCTRL_HAS_XC_INTERFACE, xenctrl.h) 

                AC_CHECK_TYPE(
                    [hvmmem_access_t],
                    [
                        have_hvmmem_access_t='yes'
                        AC_DEFINE([HAVE_HVMMEM_ACCESS_T], [1], [xenctrl defines hvmmem_access_t])],
                    [],
                    [#include <xenctrl.h> #include <xen/hvm/save.h>]
                )

                AC_CHECK_TYPE(
                    [xenmem_access_t],
                    [
                        have_xenmem_access_t='yes'
                        AC_DEFINE([HAVE_XENMEM_ACCESS_T], [1], [xenctrl defines xenmem_access_t])],
                    [],
                    [#include <xenctrl.h> #include <xen/memory.h>]
                )

                #validate that Xen events are in fact possible
                [if test "$have_XENCTRL_HAS_XC_INTERFACE" != "yes"]
                [then]
                    AC_MSG_WARN([XENCTRL_HAS_XC_INTERFACE undefined, event support disabled.])
                    have_xen_events='missing event support'
                    enable_xen_events='no'
                [else] 
                    [if test "$have_xc_mem_event_enable" = "yes" && test "$have_hvmmem_access_t" = "yes"]
                    [then]
                        have_xen_events='yes'
                        have_xen_events_legacy='yes'
                        xen_event_space=''
                        AC_DEFINE([ENABLE_XEN_EVENTS], [1], [Define to 1 to enable Xen mem events support.])
                        AC_DEFINE([XEN_EVENTS_VERSION], [410], [Define the xen events version.])
                        AC_MSG_NOTICE([4.1 style events enabled.])
                    [else]
                        [if test "$have_xc_mem_access_enable" = "yes"]
                        [then]
                            [if test "$have_hvmmem_access_t" = "yes"]
                            [then]
                                have_xen_events='yes'
                                have_xen_events_legacy='yes'
                                xen_event_space=''
                                AC_DEFINE([ENABLE_XEN_EVENTS], [1], [Define to 1 to enable Xen mem events support.])
                                AC_DEFINE([XEN_EVENTS_VERSION], [420], [Define the xen events version.])
                                AC_MSG_NOTICE([4.2 style events enabled.])
                            [else]
                                [if test "$have_xenmem_access_t" = "yes"]
                                [then]
                                    have_xen_events='yes'
                                    have_xen_events_legacy='yes'
                                    xen_event_space=''
                                    AC_DEFINE([ENABLE_XEN_EVENTS], [1], [Define to 1 to enable Xen mem events support.])
                                    AC_DEFINE([XEN_EVENTS_VERSION], [450], [Define the xen events version.])
                                    AC_MSG_NOTICE([4.5 style events enabled.])
                                [else]
                                    AC_MSG_WARN([Xen event support missing.])
                                    have_xen_events='missing event support'
                                    enable_xen_events='no'
                                [fi]
                            [fi]
                        [else]
                            [if test "$have_xc_monitor_enable" = "yes"]
                            [then]
                                    have_xen_events='yes'
                                    xen_event_space=''
                                    AC_DEFINE([ENABLE_XEN_EVENTS], [1], [Define to 1 to enable Xen mem events support.])
                                    AC_DEFINE([XEN_EVENTS_VERSION], [460], [Define the xen events version.])
                                    AC_MSG_NOTICE([4.6 style events enabled.])
                            [else]
                                AC_MSG_WARN([Xen event support missing.])
                                have_xen_events='missing event support'
                                enable_xen_events='no'
                            [fi]
                        [fi]    
                    [fi]
                [fi]
            [fi]
        [fi]
    [fi]

    AC_CHECK_TYPE(
        [vcpu_guest_context_any_t],
        AC_DEFINE([HAVE_CONTEXT_ANY], [1], [Checks existence of vcpu_guest_context_any_t to know how to check cpu context on this libxc version.]),
        [],
        [#include "xenctrl.h"])
[fi]
AM_CONDITIONAL([HAVE_XEN], [test x"$have_xen" = "xyes"])
AM_CONDITIONAL([HAVE_XEN_EVENTS], [test x"$have_xen_events" = "xyes"])
AM_CONDITIONAL([HAVE_XEN_EVENTS_LEGACY], [test x"$have_xen_events_legacy" = "xyes"])

have_kvm='no'
kvm_space='      '
[if test "$enable_kvm" = "yes"]
[then]
    AC_CHECK_LIB(virt, virConnectOpen, [], [missing="yes"])
    [if test "$missing" = "yes"]
    [then]
        AC_DEFINE([ENABLE_KVM], [0], [Define to 1 to enable KVM support.])
        missing='no'
        enable_kvm='no'
        have_kvm='libvirt missing'
    [else]
        AC_DEFINE([ENABLE_KVM], [1], [Define to 1 to enable KVM support.])
        missing='no'
        have_kvm='yes'
        kvm_space='     '
    [fi]
[fi]
AM_CONDITIONAL([HAVE_KVM], [test x"$have_kvm" = "xyes"])

have_shm_snapshot='no'
shm_snapshot_space=' '
[if test "$enable_shm_snapshot" = "yes"]
[then]
    AC_DEFINE([ENABLE_SHM_SNAPSHOT], [1], [Define to 1 to enable shm-snapshot support.])
    shm_snapshot_space=''
    have_shm_snapshot='yes'
[fi]

have_file='no'
file_space='      '
[if test "$enable_file" = "yes"]
[then]
    AC_DEFINE([ENABLE_FILE], [1], [Define to 1 to enable file support.])
    file_space='     '
    have_file='yes'
[fi]
AM_CONDITIONAL([HAVE_FILE], [test x"$have_file" = "xyes"])

[if test "$enable_windows" = "yes"]
[then]
    AC_DEFINE([ENABLE_WINDOWS], [1], [Define to 1 to Windows support.])
[fi]

[if test "$enable_linux" = "yes"]
[then]
    AC_DEFINE([ENABLE_LINUX], [1], [Define to 1 to Linux support.])
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

have_jansson='no'
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.1], [missing="no"], [missing="yes"])
[if test x"$missing" = "xno"]
[then]
        have_jansson='yes'
        AC_SUBST([JANSSON_LIBS])
        AC_SUBST([JANSSON_CFLAGS])
        AC_DEFINE([REKALL_PROFILES], [1], [Defined to 1 when working Jansson library was found to parse Rekall profiles.])
[else]
    have_jansson='Disabled, missing libjansson-dev.'
    [echo "No working Jansson library found (libjansson-dev), Rekall system profiles won't be supported."]
[fi]

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
                libvmi/config/Makefile
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

Feature      | Option                    | Reason
-------------|---------------------------|----------------------------
Xen Support  | --enable-xen=$enable_xen$xen_space     | $have_xen
Xen Events   | --enable-xen-events=$enable_xen_events$xen_event_space   | $have_xen_events
KVM Support  | --enable-kvm=$enable_kvm$kvm_space     | $have_kvm
File Support | --enable-file=$enable_file$file_space    | $have_file
Shm-snapshot | --enable-shm-snapshot=$enable_shm_snapshot$shm_snapshot_space | $have_shm_snapshot
-------------|---------------------------|----------------------------

OS           | Option                    
-------------|--------------------------------------------------------
Windows      | --enable-windows=$enable_windows
Linux        | --enable-linux=$enable_linux


Tools        | Option                    | Reason
-------------|---------------------------|----------------------------
Examples     | --enable-examples=$enable_examples$examples_space | $enable_examples
VMIFS        | --enable-vmifs=$enable_vmifs$vmifs_space  | $have_vmifs

Extra features
----------------------------------------------------------------------
Support of Rekall profiles: $have_jansson
 
If everything is correct, you can now run 'make' and (optionally)
'make install'.  Otherwise, you can run './configure' again.
])

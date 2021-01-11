h_public =  libvmi/libvmi.h \
            libvmi/libvmi_extra.h \
            libvmi/slat.h \
            libvmi/x86.h

h_private = \
    libvmi/private.h \
    libvmi/debug.h \
    libvmi/msr-index.h \
    libvmi/glib_compat.h \
    libvmi/arch/arch_interface.h \
    libvmi/arch/intel.h \
    libvmi/arch/amd64.h \
    libvmi/arch/arm_aarch32.h \
    libvmi/arch/arm_aarch64.h \
    libvmi/arch/ept.h \
    libvmi/os/os_interface.h \
    libvmi/driver/driver_interface.h \
    libvmi/driver/driver_wrapper.h \
    libvmi/driver/memory_cache.h

c_sources = \
    libvmi/accessors.c \
    libvmi/convenience.c \
    libvmi/core.c \
    libvmi/events.c \
    libvmi/pretty_print.c \
    libvmi/read.c \
    libvmi/slat.c \
    libvmi/strmatch.c \
    libvmi/write.c \
    libvmi/msr-index.c \
    libvmi/arch/arch_interface.c \
    libvmi/arch/intel.c \
    libvmi/arch/amd64.c \
    libvmi/arch/arm_aarch32.c \
    libvmi/arch/arm_aarch64.c \
    libvmi/arch/ept.c \
    libvmi/driver/driver_interface.c \
    libvmi/driver/memory_cache.c \
    libvmi/os/os_interface.c

if ENABLE_ADDRESS_CACHE
    c_sources   += libvmi/cache.c
    c_sources   += libvmi/cache.h
endif

if ENABLE_JSON_PROFILES
    c_sources   += libvmi/json_profiles/json_profiles.c
    h_private   += libvmi/json_profiles/json_profiles.h
endif

if ENABLE_VOLATILITY_IST
    c_sources   += libvmi/json_profiles/volatility_ist.c
    h_private   += libvmi/json_profiles/volatility_ist.h
endif

if ENABLE_REKALL_PROFILES
    c_sources   += libvmi/json_profiles/rekall.c
    h_private   += libvmi/json_profiles/rekall.h
endif

drivers =
if WITH_FILE
    drivers     += libvmi/driver/file/file.h \
                   libvmi/driver/file/file_private.h \
                   libvmi/driver/file/file.c
endif
if WITH_KVM
    drivers     += libvmi/driver/kvm/kvm.h \
                   libvmi/driver/kvm/kvm_private.h \
                   libvmi/driver/kvm/kvm_common.c \
                   libvmi/driver/kvm/libvirt_wrapper.c \
                   libvmi/driver/kvm/libvirt_wrapper.h

if WITH_KVM_LEGACY
    drivers += libvmi/driver/kvm/kvm_legacy.c

else
    drivers += libvmi/driver/kvm/kvm.c \
               libvmi/driver/kvm/kvm_events.c \
               libvmi/driver/kvm/kvm_events.h \
               libvmi/driver/kvm/libkvmi_wrapper.c \
               libvmi/driver/kvm/libkvmi_wrapper.h

endif
endif

if WITH_XEN
    h_public    += libvmi/events.h
    drivers     += libvmi/driver/xen/altp2m.c \
                   libvmi/driver/xen/altp2m_private.h \
                   libvmi/driver/xen/xen.h \
                   libvmi/driver/xen/xen_private.h \
                   libvmi/driver/xen/xen.c \
                   libvmi/driver/xen/xen_events.c \
                   libvmi/driver/xen/xen_events.h \
                   libvmi/driver/xen/xen_events_abi.h \
                   libvmi/driver/xen/xen_events_private.h \
                   libvmi/driver/xen/libxc_wrapper.c \
                   libvmi/driver/xen/libxc_wrapper.h \
                   libvmi/driver/xen/libxs_wrapper.c \
                   libvmi/driver/xen/libxs_wrapper.h
endif

if WITH_BAREFLANK
drivers     += libvmi/driver/bareflank/bareflank.h \
               libvmi/driver/bareflank/bareflank_private.h \
               libvmi/driver/bareflank/bareflank.c \
               libvmi/driver/bareflank/hypercall.h \
               libvmi/driver/bareflank/hypercall.S
endif

os =
if WINDOWS
h_public    += libvmi/peparse.h
os          += libvmi/os/windows/windows.h \
               libvmi/os/windows/core.c \
               libvmi/os/windows/kdbg.c \
               libvmi/os/windows/memory.c \
               libvmi/os/windows/peparse.c \
               libvmi/os/windows/process.c \
               libvmi/os/windows/unicode.c
endif
if LINUX
os          += libvmi/os/linux/linux.h \
               libvmi/os/linux/core.c \
               libvmi/os/linux/memory.c \
               libvmi/os/linux/symbols.c
endif
if FREEBSD
os          += libvmi/os/freebsd/freebsd.h \
               libvmi/os/freebsd/core.c \
               libvmi/os/freebsd/memory.c \
               libvmi/os/freebsd/symbols.c
endif

library_includedir=$(includedir)/libvmi
library_include_HEADERS = $(h_public)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libvmi.pc

AM_CPPFLAGS = -I$(top_srcdir)/libvmi
AM_YFLAGS = -y -d
AM_LDFLAGS = $(LDFLAGS)

lib_LTLIBRARIES= libvmi/libvmi.la
libvmi_libvmi_la_SOURCES= $(h_public) $(h_private) $(drivers) $(os) $(c_sources)
libvmi_libvmi_la_CFLAGS= -fvisibility=hidden $(GLIB_CFLAGS) $(JSONC_CFLAGS)
libvmi_libvmi_la_LDFLAGS= $(GLIB_LIBS) $(JSONC_LIBS) -no-undefined
libvmi_libvmi_la_LDFLAGS+= -version-info $(VERSION)

if WITH_KVM
    libvmi_libvmi_la_CFLAGS += $(LIBKVMI_CFLAGS)
endif

if ENABLE_CONFIGFILE
    config_h_sources = libvmi/config/config_parser.h
    config_c_sources = libvmi/config/grammar.y libvmi/config/lexicon.l

    CLEANFILES = libvmi/config/lexicon.c \
                 libvmi/config/grammar.c \
                 libvmi/config/grammar.h

    noinst_LTLIBRARIES= libvmi/config/libconfig.la
    libvmi_config_libconfig_la_SOURCES= $(config_h_sources) $(config_c_sources)
    libvmi_config_libconfig_la_CFLAGS= $(GLIB_CFLAGS)
    libvmi_config_libconfig_la_LDFLAGS= $(GLIB_LIBS)

    libvmi_libvmi_la_LIBADD= libvmi/config/libconfig.la
endif

if HARDENING
    libvmi_libvmi_la_CFLAGS  += $(HARDEN_CFLAGS)
    libvmi_libvmi_la_LDFLAGS += $(HARDEN_LDFLAGS)
endif

if DEBUG
    libvmi_libvmi_la_CFLAGS+= -Wall -Wextra
    libvmi_libvmi_la_CFLAGS+= -Werror
    libvmi_libvmi_la_CFLAGS+= -Wno-missing-field-initializers
    libvmi_libvmi_la_CFLAGS+= -Wno-missing-braces
    libvmi_libvmi_la_CFLAGS+= -Wno-unused-result
    libvmi_libvmi_la_CFLAGS+= -Wno-ignored-attributes
endif

#############################################################

bin_PROGRAMS =
noinst_PROGRAMS =

if VMIFS
    tools_vmifs_vmifs_CFLAGS = $(FUSE_CFLAGS) $(GLIB_CFLAGS) -DFUSE_USE_VERSION=22
    tools_vmifs_vmifs_LDADD = $(FUSE_LIBS) $(GLIB_LIBS) libvmi/libvmi.la

    bin_PROGRAMS += tools/vmifs/vmifs
    tools_vmifs_vmifs_SOURCES = tools/vmifs/vmifs.c
endif

if EXAMPLES
    LDADD = libvmi/libvmi.la

    bin_PROGRAMS += examples/vmi-process-list \
                    examples/vmi-module-list \
                    examples/vmi-dump-memory

if WINDOWS
    bin_PROGRAMS += examples/vmi-win-guid \
                    examples/vmi-win-offsets

    examples_vmi_win_offsets_CFLAGS = $(GLIB_CFLAGS)
    examples_vmi_win_offsets_LDADD = $(GLIB_LIBS) libvmi/libvmi.la
    examples_vmi_win_guid_CFLAGS = $(GLIB_CFLAGS)
    examples_vmi_win_guid_LDADD = $(GLIB_LIBS) libvmi/libvmi.la
endif

if LINUX
    bin_PROGRAMS += examples/vmi-dmesg
    examples_vmi_dmesg_SOURCES = examples/dmesg.c
endif

    examples_vmi_process_list_SOURCES = examples/process-list.c
    examples_vmi_module_list_SOURCES = examples/module-list.c
    examples_vmi_dump_memory_SOURCES = examples/dump-memory.c
    examples_vmi_win_guid_SOURCES = examples/win-guid.c examples/win-guid.h
    examples_vmi_win_offsets_SOURCES = examples/win-offsets.c

    noinst_PROGRAMS += examples/map-symbol \
                       examples/map-addr \
                       examples/event-example \
                       examples/msr-event-example \
                       examples/singlestep-event-example \
                       examples/interrupt-event-example \
                       examples/step-event-example \
                       examples/xen-emulate-response \
                       examples/breakpoint-emulate-example

    examples_map_symbol_SOURCES = examples/map-symbol.c
    examples_map_addr_SOURCES = examples/map-addr.c
    examples_event_example_SOURCES = examples/event-example.c
    examples_msr_event_example_SOURCES = examples/msr-event-example.c
    examples_singlestep_event_example_SOURCES = examples/singlestep-event-example.c
    examples_interrupt_event_example_SOURCES = examples/interrupt-event-example.c
    examples_step_event_example_SOURCES = examples/step-event-example.c
    examples_xen_emulate_response_SOURCES = examples/xen-emulate-response.c
    examples_breakpoint_emulate_example_SOURCES = examples/breakpoint-emulate-example.c

    noinst_PROGRAMS += examples/va-pages
    examples_va_pages_SOURCES = examples/va-pages.c
    examples_va_pages_CFLAGS = $(GLIB_CFLAGS)
    examples_va_pages_LDADD = $(GLIB_LIBS) libvmi/libvmi.la
endif

#############################################################

if MAKE_TESTS
    TESTS = tests/check_libvmi

    check_PROGRAMS = tests/check_libvmi

    tests_check_libvmi_SOURCES = \
        tests/check_runner.c \
        tests/check_tests.h \
        tests/test_accessor.c \
        tests/test_init.c \
        tests/test_print.c \
        tests/test_read.c \
        tests/test_translate.c \
        tests/test_util.c \
        tests/test_write.c \
        tests/test_peparse.c \
        tests/test_cache.c \
        tests/test_getvapages.c

    tests_check_libvmi_CFLAGS = $(CHECK_CFLAGS) $(GLIB_CFLAGS)
    tests_check_libvmi_LDADD = $(CHECK_LIBS) $(GLIB_LIBS) libvmi/libvmi.la
endif

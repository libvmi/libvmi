
# add_subdirectory(config)

if (ENABLE_FILE)
    set(file_driver_src
        driver/file/file.c
    )

    add_library(file_driver SHARED ${file_driver_src})
    target_include_directories(file_driver PRIVATE ${GLIB_INCLUDE_DIRS})
endif (ENABLE_FILE)

if (ENABLE_KVM)
    set(kvm_driver_src
        driver/kvm/kvm.c
        driver/kvm/libvirt_wrapper.c
    )

    add_library(kvm_driver SHARED ${kvm_driver_src})
    target_include_directories(kvm_driver PRIVATE ${GLIB_INCLUDE_DIRS})
    # CMAKE_DL_LIBS -> dlopen* lib
    target_link_libraries(kvm_driver ${CMAKE_DL_LIBS} ${JSON-C_LIBRARIES})
endif (ENABLE_KVM)


if (ENABLE_XEN)
    set(xen_driver_src
        driver/xen/altp2m.c
        driver/xen/altp2m_private.h
        driver/xen/xen.h
        driver/xen/xen_private.h
        driver/xen/xen.c
        driver/xen/xen_events.c
        driver/xen/xen_events.h
        driver/xen/xen_events_private.h
        driver/xen/xen_events_46.c
        driver/xen/xen_events_48.c
        driver/xen/xen_events_legacy.c
        driver/xen/libxc_wrapper.c
        driver/xen/libxc_wrapper.h
        driver/xen/libxs_wrapper.c
        driver/xen/libxs_wrapper.h
    )

    add_library(xen_driver SHARED ${xen_driver_src})
    target_include_directories(xen_driver PRIVATE ${GLIB_INCLUDE_DIRS})
endif (ENABLE_XEN)

if (ENABLE_WINDOWS)
    set(windows_src
        os/windows/core.c
        os/windows/kdbg.c
        os/windows/memory.c
        os/windows/peparse.c
        os/windows/process.c
        os/windows/unicode.c
    )

    add_library(windows SHARED ${windows_src})
    target_include_directories(windows PRIVATE ${GLIB_INCLUDE_DIRS})
endif (ENABLE_WINDOWS)

if (ENABLE_LINUX)
    set(linux_src
        os/linux/core.c
        os/linux/memory.c
        os/linux/symbols.c
    )

    add_library(linux SHARED ${linux_src})
    target_include_directories(linux PRIVATE ${GLIB_INCLUDE_DIRS})
endif (ENABLE_LINUX)

if (ENABLE_FREEBSD)
    set(freebsd_src
        os/freebsd/core.c
        os/freebsd/memory.c
        os/freebsd/symbols.c
    )

    add_library(freebsd SHARED ${freebsd_src})
    target_include_directories(freebsd PRIVATE ${GLIB_INCLUDE_DIRS})
endif (ENABLE_FREEBSD)

if (ENABLE_ADDRESS_CACHE)
    add_library(cache SHARED cache.c)
    target_include_directories(cache PRIVATE ${GLIB_INCLUDE_DIRS})
endif (ENABLE_ADDRESS_CACHE)

if (ENABLE_SHM_SNAPSHOT)
    add_library(shm SHARED shm.c)
    target_include_directories(shm PRIVATE ${GLIB_INCLUDE_DIRS})
endif (ENABLE_SHM_SNAPSHOT)

set(libvmi_src
    accessors.c
    convenience.c
    core.c
    events.c
    performance.c
    pretty_print.c
    read.c
    slat.c
    strmatch.c
    write.c
    memory.c
    arch/arch_interface.c
    arch/intel.c
    arch/amd64.c
    arch/arm_aarch32.c
    arch/arm_aarch64.c
    driver/driver_interface.c
    driver/memory_cache.c
    os/os_interface.c
)

add_library(vmi SHARED
    ${libvmi_src}
)
# one of our public header exposes glib
# vmi_get_va_pages returns a GList*
target_include_directories(vmi PUBLIC ${GLIB_INCLUDE_DIRS})
target_link_libraries(vmi ${GLIB_LDFLAGS} m)

if (ENABLE_WINDOWS)
    target_link_libraries(vmi windows)
endif (ENABLE_WINDOWS)

if (ENABLE_LINUX)
    target_link_libraries(vmi linux)
endif (ENABLE_LINUX)

if (ENABLE_FREEBSD)
    target_link_libraries(vmi freebsd)
endif (ENABLE_FREEBSD)

if (ENABLE_FILE)
    target_link_libraries(vmi file_driver)
endif (ENABLE_FILE)

if (ENABLE_KVM)
    target_link_libraries(vmi kvm_driver)
endif (ENABLE_KVM)

if (ENABLE_XEN)
    target_link_libraries(vmi xen_driver)
endif (ENABLE_XEN)

if (ENABLE_ADDRESS_CACHE)
    target_link_libraries(vmi cache)
endif (ENABLE_ADDRESS_CACHE)

if (ENABLE_SHM_SNAPSHOT)
    target_link_libraries(vmi shm)
endif (ENABLE_SHM_SNAPSHOT)

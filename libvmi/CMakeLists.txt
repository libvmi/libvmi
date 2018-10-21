add_subdirectory(config)
add_subdirectory(driver)

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
endif ()

if (ENABLE_LINUX)
    set(linux_src
        os/linux/core.c
        os/linux/memory.c
        os/linux/symbols.c
    )

    add_library(linux SHARED ${linux_src})
    target_include_directories(linux PRIVATE ${GLIB_INCLUDE_DIRS})
endif ()

if (ENABLE_FREEBSD)
    set(freebsd_src
        os/freebsd/core.c
        os/freebsd/memory.c
        os/freebsd/symbols.c
    )

    add_library(freebsd SHARED ${freebsd_src})
    target_include_directories(freebsd PRIVATE ${GLIB_INCLUDE_DIRS})
endif ()

if (ENABLE_ADDRESS_CACHE)
    add_library(cache SHARED cache.c)
    target_include_directories(cache PRIVATE ${GLIB_INCLUDE_DIRS})
endif ()

if (ENABLE_SHM_SNAPSHOT)
    add_library(shm SHARED shm.c)
    target_include_directories(shm PRIVATE ${GLIB_INCLUDE_DIRS})
endif ()

if (REKALL_PROFILES)
    add_library(rekall SHARED rekall.c)
    target_include_directories(rekall PRIVATE ${GLIB_INCLUDE_DIRS})
endif ()

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
endif ()

if (ENABLE_LINUX)
    target_link_libraries(vmi linux)
endif ()

if (ENABLE_FREEBSD)
    target_link_libraries(vmi freebsd)
endif ()

if (ENABLE_FILE)
    target_link_libraries(vmi file_driver)
endif ()

if (ENABLE_KVM)
    target_link_libraries(vmi kvm_driver)
endif ()

if (ENABLE_XEN)
    target_link_libraries(vmi xen_driver)
endif ()

if (ENABLE_ADDRESS_CACHE)
    target_link_libraries(vmi cache)
endif ()

if (ENABLE_SHM_SNAPSHOT)
    target_link_libraries(vmi shm)
endif ()

if (REKALL_PROFILES)
    target_link_libraries(vmi rekall)
endif ()

if (ENABLE_CONFIGFILE)
    target_link_libraries(vmi config)
endif ()

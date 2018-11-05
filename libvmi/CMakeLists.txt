set(VMI_PUBLIC_HEADERS
    libvmi.h
    libvmi_extra.h
    slat.h
    x86.h)

add_subdirectory(config)
add_subdirectory(driver)
add_subdirectory(os)

if (ENABLE_ADDRESS_CACHE)
    add_library(cache SHARED cache.c)
    target_include_directories(cache PRIVATE ${GLIB_INCLUDE_DIRS})
endif ()

if (ENABLE_SHM_SNAPSHOT)
    add_library(shm SHARED shm.c)
    target_include_directories(shm PRIVATE ${GLIB_INCLUDE_DIRS})
    list(APPEND VMI_PUBLIC_HEADERS shm.h)
endif ()

if (REKALL_PROFILES)
    find_package(JSON-C REQUIRED)
    add_library(rekall SHARED rekall.c)
    target_include_directories(rekall PRIVATE ${GLIB_INCLUDE_DIRS} ${JSON-C_INCLUDE_DIRS})
    target_link_libraries(rekall ${JSON-C_LIBRARIES})
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


if (ENABLE_FREEBSD)
    target_link_libraries(vmi freebsd)
endif ()

if (ENABLE_LINUX)
    target_link_libraries(vmi linux)
endif ()

if (ENABLE_WINDOWS)
    target_link_libraries(vmi windows)
    list(APPEND VMI_PUBLIC_HEADERS peparse.h)
endif ()

if (ENABLE_FILE)
    target_link_libraries(vmi file_driver)
endif ()

if (ENABLE_KVM)
    target_link_libraries(vmi kvm_driver)
endif ()

if (ENABLE_XEN)
    target_link_libraries(vmi xen_driver)
    list(APPEND VMI_PUBLIC_HEADERS events.h)
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

# install
get_property(LIB64 GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS)

if ("${LIB64}" STREQUAL "TRUE")
    set(LIBSUFFIX 64)
else()
    set(LIBSUFFIX "")
endif()
install(TARGETS vmi DESTINATION lib${LIBSUFFIX})
install(FILES ${VMI_PUBLIC_HEADERS} DESTINATION include/libvmi)

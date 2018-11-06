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
endif ()

if (ENABLE_SHM_SNAPSHOT)
    add_library(shm SHARED shm.c)
    list(APPEND VMI_PUBLIC_HEADERS shm.h)
endif ()

if (REKALL_PROFILES)
    find_package(JSON-C REQUIRED)
    add_library(rekall SHARED rekall.c)
    target_include_directories(rekall PRIVATE ${JSON-C_INCLUDE_DIRS})
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

add_library(vmi OBJECT ${libvmi_src})
# force -fPIC
set_property(TARGET vmi PROPERTY POSITION_INDEPENDENT_CODE ON)

# create libvmi.so
add_library (vmi_shared SHARED $<TARGET_OBJECTS:vmi>)
target_link_libraries(vmi_shared ${GLIB_LDFLAGS} m)
set_target_properties(vmi_shared PROPERTIES OUTPUT_NAME "vmi")
# set soname
set_target_properties(vmi_shared PROPERTIES
    VERSION
    ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)
if (ENABLE_STATIC)
    # create libvmi.a
    add_library (vmi_static STATIC $<TARGET_OBJECTS:vmi>)
    set_target_properties(vmi_static PROPERTIES OUTPUT_NAME "vmi")
endif ()

if (ENABLE_FREEBSD)
    target_link_libraries(vmi_shared freebsd)
endif ()

if (ENABLE_LINUX)
    target_link_libraries(vmi_shared linux)
endif ()

if (ENABLE_WINDOWS)
    target_link_libraries(vmi_shared windows)
    list(APPEND VMI_PUBLIC_HEADERS peparse.h)
endif ()

if (ENABLE_FILE)
    target_link_libraries(vmi_shared file_driver)
endif ()

if (ENABLE_KVM)
    target_link_libraries(vmi_shared kvm_driver)
endif ()

if (ENABLE_XEN)
    target_link_libraries(vmi_shared xen_driver)
    list(APPEND VMI_PUBLIC_HEADERS events.h)
endif ()

if (ENABLE_ADDRESS_CACHE)
    target_link_libraries(vmi_shared cache)
endif ()

if (ENABLE_SHM_SNAPSHOT)
    target_link_libraries(vmi_shared shm)
endif ()

if (REKALL_PROFILES)
    target_link_libraries(vmi_shared rekall)
endif ()

if (ENABLE_CONFIGFILE)
    target_link_libraries(vmi_shared config)
endif ()

# install
get_property(LIB64 GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS)

if ("${LIB64}" STREQUAL "TRUE")
    set(LIBSUFFIX 64)
else()
    set(LIBSUFFIX "")
endif()

install(TARGETS vmi_shared DESTINATION lib${LIBSUFFIX})
if (ENABLE_STATIC)
    install(TARGETS vmi_static DESTINATION lib${LIBSUFFIX})
endif ()
install(FILES ${VMI_PUBLIC_HEADERS} DESTINATION include/libvmi)

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

set(VMI_PUBLIC_HEADERS
    libvmi.h
    libvmi_extra.h
    slat.h
    x86.h)



# create libvmi.so
add_library (vmi_shared SHARED $<TARGET_OBJECTS:vmi>)
target_link_libraries(vmi_shared PUBLIC ${GLIB_LDFLAGS} m)
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

add_subdirectory(config)
add_subdirectory(driver)
add_subdirectory(os)

if (ENABLE_KVM)
    find_package(JSON-C REQUIRED)
    find_package(Libvirt REQUIRED)
    target_include_directories(vmi_shared PRIVATE ${JSON-C_INCLUDE_DIRS})
    # CMAKE_DL_LIBS -> dlopen* lib
    target_link_libraries(vmi_shared PUBLIC ${CMAKE_DL_LIBS} ${JSON-C_LIBRARIES})
    if (ENABLE_SHM_SNAPSHOT)
        # shm_open/shm_unlink are provided by -lrt
        target_link_libraries(vmi_shared PUBLIC rt)
    endif ()
endif ()

if (ENABLE_XEN)
    find_package(Xen REQUIRED)
    list(APPEND VMI_PUBLIC_HEADERS events.h)
    if (ENABLE_XENSTORE)
        find_package(Xenstore REQUIRED)
    endif ()
    # CMAKE_DL_LIBS -> dlopen* lib
    target_link_libraries(vmi_shared PUBLIC ${CMAKE_DL_LIBS})
endif ()

if (ENABLE_WINDOWS)
    list(APPEND VMI_PUBLIC_HEADERS peparse.h)
endif ()

if (ENABLE_ADDRESS_CACHE)
    target_sources(vmi_shared PRIVATE cache.c)
endif ()

if (ENABLE_SHM_SNAPSHOT)
    target_sources(vmi_shared PRIVATE shm.c)
    list(APPEND VMI_PUBLIC_HEADERS shm.h)
endif ()

if (REKALL_PROFILES)
    find_package(JSON-C REQUIRED)
    target_sources(vmi_shared PRIVATE rekall.c)
    target_include_directories(vmi_shared PUBLIC ${JSON-C_INCLUDE_DIRS})
    target_link_libraries(vmi_shared PUBLIC ${JSON-C_LIBRARIES})
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

# expand ${VAR}
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libtool_template.in
    ${CMAKE_CURRENT_BINARY_DIR}/libtool_template.gen)

# expand $<EXPRESSION>
file(GENERATE
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libvmi.la
    INPUT ${CMAKE_CURRENT_BINARY_DIR}/libtool_template.gen)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libvmi.la DESTINATION lib${LIBSUFFIX})

set(libvmi_src
    accessors.c
    convenience.c
    core.c
    events.c
    pretty_print.c
    read.c
    slat.c
    strmatch.c
    write.c
    msr-index.c
    arch/arch_interface.c
    arch/intel.c
    arch/amd64.c
    arch/arm_aarch32.c
    arch/arm_aarch64.c
    arch/ept.c
    driver/driver_interface.c
    driver/memory_cache.c
    os/os_interface.c
    disk/vbd.c
)

add_library(vmi OBJECT ${libvmi_src})
# force -fPIC
set_property(TARGET vmi PROPERTY POSITION_INDEPENDENT_CODE ON)

set(VMI_PUBLIC_HEADERS
    libvmi.h
    libvmi_extra.h
    slat.h
    x86.h)

# list of external dependencies, used by libtool for the static library
set(VMI_PUBLIC_DEPS "")

# create libvmi.so
add_library (vmi_shared SHARED $<TARGET_OBJECTS:vmi>)
# one libvmi_extra.h function returns a GSList*
target_link_libraries(vmi_shared PUBLIC ${GLIB_LIBRARIES})
list(APPEND VMI_PUBLIC_DEPS ${GLIB_LIBRARIES})
set_target_properties(vmi_shared PROPERTIES OUTPUT_NAME "vmi")
# set soname
set_target_properties(vmi_shared PROPERTIES
    VERSION
    0.${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    SOVERSION 0
)
if (ENABLE_STATIC)
    # create libvmi.a
    add_library (vmi_static STATIC $<TARGET_OBJECTS:vmi>)
    set_target_properties(vmi_static PROPERTIES OUTPUT_NAME "vmi")
endif ()

if (ZLIB_FOUND)
    target_link_libraries(vmi_shared PUBLIC ${ZLIB_LIBRARIES})
    list(APPEND VMI_PUBLIC_DEPS ${ZLIB_LIBRARIES})
endif ()

# workaround CMake bug
# target_sources doesn't work with generated files in subdirectories
if (ENABLE_CONFIGFILE)
    find_package(FLEX)
    set_package_properties(FLEX PROPERTIES
        DESCRIPTION "Scanner generator for lexing in C and C++"
        URL "https://github.com/westes/flex"
        TYPE OPTIONAL
        PURPOSE "Lexing LibVMI configuration file")
    find_package(BISON)
    set_package_properties(BISON PROPERTIES
        DESCRIPTION "Parser generator"
        URL "https://www.gnu.org/software/bison"
        TYPE OPTIONAL
        PURPOSE "Parsing LibVMI configuration file")
    if (NOT FLEX_FOUND OR NOT BISON_FOUND)
        set(ENABLE_CONFIGFILE OFF CACHE BOOL "Enable config file" FORCE)
        message(WARNING "Cannot find flex or bison: config file parsing will be
        disabled")
    else ()
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
            COMMAND ${FLEX_EXECUTABLE}
                --outfile=${CMAKE_CURRENT_BINARY_DIR}/scanner.c
                ${CMAKE_CURRENT_SOURCE_DIR}/config/lexicon.l
            COMMENT "Generating scanner.c"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/config
        )

        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/parser.c
            COMMAND ${BISON_EXECUTABLE}
                --output=${CMAKE_CURRENT_BINARY_DIR}/parser.c
                --defines=${CMAKE_CURRENT_BINARY_DIR}/grammar.h
                ${CMAKE_CURRENT_SOURCE_DIR}/config/grammar.y
            COMMENT "Generating parser.c"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/config
        )

        # build specific target for scanner.c and parser.c
        # to remove Werror flag, otherwise flex and bison's generated
        # source file won't compile
        add_library(config_parser STATIC
            ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
            ${CMAKE_CURRENT_BINARY_DIR}/parser.c
        )

        target_include_directories(config_parser PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR} # grammar.h
            ${CMAKE_CURRENT_SOURCE_DIR}/config # config_parser.h
        )
        # remove Werror flag just for config_parser
        # compile with -fPIC to allow static linking
        set_target_properties(config_parser PROPERTIES COMPILE_FLAGS "-Wno-error -fPIC")
        # link with main libvmi library
        target_link_libraries(vmi_shared PRIVATE config_parser)
    endif ()
endif ()

if (ENABLE_KVM)
    # common dependencies
    find_package(Libvirt)
    if (NOT Libvirt_FOUND)
        set(ENABLE_KVM OFF CACHE BOOL "Build KVM driver" FORCE)
        message(WARNING "Cannot find libvirt: disabling KVM driver")
    else ()
        if (ENABLE_KVM_LEGACY)
            # legacy KVM driver
            target_link_libraries(vmi_shared PRIVATE m)
            find_package(JSON-C)
            set_package_properties(JSON-C PROPERTIES
                PURPOSE "Dependency for KVM driver")
            if (NOT JSON-C_FOUND)
                set(ENABLE_KVM OFF CACHE BOOL "Build KVM driver" FORCE)
                message(WARNING "Cannot find JSON: disabling KVM driver")
            else ()
                find_package(LibvmiRequest)
            endif ()
        else ()
            # KVM driver based on KVMi series, API is exposed via libkvmi
            pkg_search_module(Libkvmi libkvmi)
            if (NOT Libkvmi_FOUND)
                set(ENABLE_KVM OFF CACHE BOOL "Build KVM driver" FORCE)
                message(WARNING "Cannot find libkvmi: disabling KVM driver")
            else ()
                message("Found libkvmi headers: ${Libkvmi_INCLUDE_DIRS}")
                target_include_directories(vmi_shared PRIVATE ${Libkvmi_INCLUDE_DIRS})
            endif ()
        endif ()
        target_include_directories(vmi_shared PRIVATE ${JSON-C_INCLUDE_DIRS})
        # CMAKE_DL_LIBS -> dlopen* lib
        target_link_libraries(vmi_shared PRIVATE ${CMAKE_DL_LIBS} ${JSON-C_LIBRARIES})
        list(APPEND VMI_PUBLIC_HEADERS events.h)
        list(APPEND VMI_PUBLIC_DEPS ${CMAKE_DL_LIBS} ${JSON-C_LIBRARIES})
    endif ()
endif ()


if (ENABLE_BAREFLANK)
    find_package(JSON-C)
    set_package_properties(JSON-C PROPERTIES
        PURPOSE "Dependency for Bareflank driver")
    if (NOT JSON-C_FOUND)
        set(ENABLE_BAREFLANK OFF CACHE BOOL "Build Bareflank driver" FORCE)
        message(WARNING "Cannot find JSON: disabling Bareflank driver")
    else ()
        target_include_directories(vmi_shared PRIVATE ${JSON-C_INCLUDE_DIRS})
        target_link_libraries(vmi_shared PRIVATE ${JSON-C_LIBRARIES})
        list(APPEND VMI_PUBLIC_DEPS ${JSON-C_LIBRARIES})
    endif ()
endif ()

add_subdirectory(driver)
add_subdirectory(os)


if (ENABLE_XEN)
    find_package(Xen REQUIRED)
    list(APPEND VMI_PUBLIC_HEADERS events.h)
    # CMAKE_DL_LIBS -> dlopen* lib
    target_link_libraries(vmi_shared PRIVATE ${CMAKE_DL_LIBS})
    list(APPEND VMI_PUBLIC_DEPS ${CMAKE_DL_LIBS})
endif ()

if (ENABLE_WINDOWS)
    list(APPEND VMI_PUBLIC_HEADERS peparse.h)
endif ()

if (ENABLE_ADDRESS_CACHE)
    target_sources(vmi_shared PRIVATE cache.c)
endif ()

if (REKALL_PROFILES OR VOLATILITY_IST)
    find_package(JSON-C)
    set_package_properties(JSON-C PROPERTIES
        PURPOSE "Dependency for Rekall profiles and Volatility IST parsing")
    if (NOT JSON-C_FOUND)
        set(ENABLE_JSON_PROFILES OFF CACHE BOOL "Enable JSON Profiles" FORCE)
        set(REKALL_PROFILES OFF CACHE BOOL "" FORCE)
        set(VOLATILITY_IST OFF CACHE BOOL "" FORCE)
        message(WARNING "Cannot find JSON: disabling Rekall profiles and Volatility IST")
    else ()
        set(ENABLE_JSON_PROFILES ON)
        target_sources(vmi_shared PRIVATE json_profiles/json_profiles.c)
        if (REKALL_PROFILES)
            target_sources(vmi_shared PRIVATE json_profiles/rekall.c)
        endif ()
        if (VOLATILITY_IST)
            target_sources(vmi_shared PRIVATE json_profiles/volatility_ist.c)
        endif ()
        target_include_directories(vmi_shared PRIVATE ${JSON-C_INCLUDE_DIRS})
        target_link_libraries(vmi_shared PRIVATE ${JSON-C_LIBRARIES})
        list(APPEND VMI_PUBLIC_DEPS ${JSON-C_LIBRARIES})
    endif ()
endif ()

install(TARGETS vmi_shared DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})
if (ENABLE_STATIC)
    install(TARGETS vmi_static DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})
endif ()
install(FILES ${VMI_PUBLIC_HEADERS} DESTINATION include/libvmi)

list(REMOVE_DUPLICATES VMI_PUBLIC_DEPS)
set (DEPENDENCY_LIBS "")
foreach (PUB_LIB ${VMI_PUBLIC_DEPS})
    set(DEPENDENCY_LIBS "${DEPENDENCY_LIBS} -l${PUB_LIB}")
endforeach ()
# expand ${VAR}
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libtool_template.in
    ${CMAKE_CURRENT_BINARY_DIR}/libtool_template.gen)

# expand $<EXPRESSION>
file(GENERATE
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libvmi.la
    INPUT ${CMAKE_CURRENT_BINARY_DIR}/libtool_template.gen)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libvmi.la DESTINATION
    ${CMAKE_INSTALL_FULL_LIBDIR})

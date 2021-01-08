cmake_minimum_required(VERSION 3.1)

# set cmake module path, to search in cmake/modules first
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")
#-----------------------------------------------------------------------------
#                           GENERAL CONFIGURATION
#-----------------------------------------------------------------------------
project(LibVMI VERSION 0.15.0 LANGUAGES C ASM)
set(VERSION "0.15.0")

# build type
set(default_build_type "Debug")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
    set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
        STRING "Choose the type of build." FORCE)
    # Set the possible values of build type for cmake-gui
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()
#-----------------------------------------------------------------------------
#                              DEPENDENCIES
#-----------------------------------------------------------------------------
include(FeatureSummary)
find_package(PkgConfig REQUIRED)
set_package_properties(PkgConfig PROPERTIES
    DESCRIPTION "Helper tool to compile applications and libraries"
    URL "https://www.freedesktop.org/wiki/Software/pkg-config/"
    TYPE REQUIRED
    PURPOSE "Find and configure multiple LibVMI dependencies")
pkg_search_module(GLIB REQUIRED glib-2.0)
# cleanup GLIB_LDFLAGS (remove -l prefix)
string(REGEX REPLACE "-l" "" GLIB_LDFLAGS ${GLIB_LDFLAGS})

include(DetectArchitecture)
include(StaticAnalysis)
include(GNUInstallDirs)
#-----------------------------------------------------------------------------
#                           BUILD TYPES & FLAGS
#-----------------------------------------------------------------------------
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Werror -O2")

# default hardening flags that have no performance hit
set(HARDENING_LINKER_FLAGS "-Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now")
# update default flags
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${HARDENING_LINKER_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${HARDENING_LINKER_FLAGS}")

# strip library in release mode
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "-s")
#-----------------------------------------------------------------------------
#                             BUILD OPTIONS
#-----------------------------------------------------------------------------
option(ENABLE_XEN "Build Xen driver" ON)
option(ENABLE_FILE "Build file driver" ON)

option(ENABLE_WINDOWS "Build Windows introspection" ON)
option(ENABLE_LINUX "Build Linux introspection" ON)
option(ENABLE_FREEBSD "Build FreeBSD introspection" ON)

option(ENABLE_STATIC "Build libvmi static library" ON)

option(ENABLE_XENSTORE "Build with Xenstore" ON)
option(ENABLE_VMIFS "Enable vmifs: maps memory to a file through FUSE" ON)
option(ENABLE_CONFIGFILE "Enable config file" ON)
option(ENABLE_ADDRESS_CACHE "Enable address cache" ON)
option(ENABLE_PAGE_CACHE "Enable page cache" ON)
option(ENABLE_SAFETY_CHECKS "Enable API safety checks" ON)
option(ENABLE_TESTING "Build libvmi test suite" OFF)
option(BUILD_EXAMPLES "Build the examples" ON)
# See libvmi/debug.h for possible debug levels
option(VMI_DEBUG "Debug output level" OFF)
# hardening flags that causes overhead, disabled by default
option(HARDENING "Enable hardening flags (with overhead)" OFF)
option(ENV_DEBUG "Toggle the debug output via LIBVMI_DEBUG environment variable" OFF)
option(ENABLE_KVM_LEGACY "Build KVM legacy driver" OFF)

# jsonc
# check JSONC_UINT64_SUPPORT
# for some reason it's impossible to override the default options that get defined here
# further down in the chain (ie. in libvmi/CMakeLists.txt)
find_package(JSON-C)
if (JSON-C_FOUND)
    if (JSON-C_VERSION VERSION_EQUAL 0.15 OR JSON-C_VERSION VERSION_GREATER 0.15)
        set(JSONC_UINT64_SUPPORT ON)
    endif ()
    option(ENABLE_KVM "Build KVM driver" ON)
    option(ENABLE_BAREFLANK "Build Bareflank driver" ON)
    option(ENABLE_JSON_PROFILES "Enable JSON profiles" ON)
    option(REKALL_PROFILES "Support Rekall's JSON profiles" ON)
    option(VOLATILITY_IST "Support Volatility's JSON ISTs" ON)
    # check HAVE_LIBVMI_REQUEST
    # for some reason it's impossible to override the default options that get defined here
    # further down in the chain (ie. in libvmi/CMakeLists.txt)
    if (ENABLE_KVM AND ENABLE_KVM_LEGACY)
        find_package(LibvmiRequest)
    endif ()
else ()
    message(STATUS "JSON-C library was not found, KVM, Bareflank & JSON profile support is disabled")
    option(ENABLE_KVM "Build KVM driver" OFF)
    option(ENABLE_BAREFLANK "Build Bareflank driver" OFF)
    option(ENABLE_JSON_PROFILES "Enable JSON profiles" OFF)
    option(REKALL_PROFILES "Support Rekall's JSON profiles" OFF)
    option(VOLATILITY_IST "Support Volatility's JSON ISTs" OFF)
endif ()

# default values
set(MAX_PAGE_CACHE_SIZE "512")

# enable hardening if requested
if (HARDENING)
    # enable stack canaries, not all because the performance cost is too high
    # -fstack-protector-strong appears since GCC 4.9
    # we assume Debian Stretch at least, so GCC 6.3.0
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
    # enforce position independant code
    set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
    # enforce pie
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
    # enforce fortify source
    # we should use add_compile_definitions, but only available since
    # CMake 3.12.0 (assuming 3.1)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2")
endif ()

if (ENABLE_XEN AND ENABLE_XENSTORE)
    find_package(Xenstore REQUIRED)
endif ()

#-----------------------------------------------------------------------------
#                               SOURCES
#-----------------------------------------------------------------------------
configure_file(libvmi.pc.in ${PROJECT_BINARY_DIR}/libvmi.pc)
install(FILES ${PROJECT_BINARY_DIR}/libvmi.pc DESTINATION
    "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig")

# include <libvmi/libvmi.h> "config.h", "private.h" and <glib.h>
include_directories(${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR} libvmi ${GLIB_INCLUDE_DIRS})
add_definitions(-DHAVE_CONFIG_H)
add_subdirectory(libvmi)
# configure config.h after processing libvmi subdir
# as it may have disabled some features due to unmet dependencies
configure_file(libvmi/config.h.in ${PROJECT_BINARY_DIR}/config.h)
add_subdirectory(tools)
if (ENABLE_TESTING)
    # this command should always be called in the root CMakeLists.txt
    enable_testing()
    add_subdirectory(tests)
endif (ENABLE_TESTING)

if (BUILD_EXAMPLES)
    add_subdirectory(examples)
endif (BUILD_EXAMPLES)
add_subdirectory(doc)
#-----------------------------------------------------------------------------
#                               BUILD SUMMARY
#-----------------------------------------------------------------------------
add_feature_info(ENABLE_XEN ENABLE_XEN "Build Xen driver")
add_feature_info(ENABLE_KVM ENABLE_KVM "Build KVM driver")
add_feature_info(ENABLE_BAREFLANK ENABLE_BAREFLANK "Build Bareflank driver")
add_feature_info(ENABLE_FILE ENABLE_FILE "Build file driver")

add_feature_info(ENABLE_WINDOWS ENABLE_WINDOWS "Enable Windows introspection")
add_feature_info(ENABLE_LINUX ENABLE_LINUX "Enable Linux introspection")
add_feature_info(ENABLE_FREEBSD ENABLE_FREEBSD "Enable FreeBSD introspection")

add_feature_info(ENABLE_STATIC ENABLE_STATIC "Build LibVMI static library")

add_feature_info(ENABLE_XENSTORE ENABLE_XENSTORE "Build Xen driver with Xenstore")
add_feature_info(ENABLE_VMIFS ENABLE_VMIFS "Enable vmifs: maps memory to a file through FUSE")
add_feature_info(ENABLE_CONFIGFILE ENABLE_CONFIGFILE "Enable config file")
add_feature_info(ENABLE_ADDRESS_CACHE ENABLE_ADDRESS_CACHE "Enable address cache")
add_feature_info(ENABLE_PAGE_CACHE ENABLE_PAGE_CACHE "Enable page cache")
add_feature_info(REKALL_PROFILES REKALL_PROFILES "Support Rekall's JSON profiles")
add_feature_info(VOLATILITY_IST VOLATILITY_IST "Support Volatility's JSON ISTs")
add_feature_info(ENABLE_SAFETY_CHECKS ENABLE_SAFETY_CHECKS "Enable API safety checks")
add_feature_info(ENABLE_TESTING ENABLE_TESTING "Enable LibVMI test suite")
add_feature_info(BUILD_EXAMPLES BUILD_EXAMPLES "Build the examples")
add_feature_info(ENABLE_KVM_LEGACY ENABLE_KVM_LEGACY "Build KVM legacy driver")
message(STATUS " ↳ Compiler     → ${CMAKE_C_COMPILER}")
message(STATUS " ↳ C Flags      → ${CMAKE_C_FLAGS}")
message(STATUS " ↳ Prefix       → ${CMAKE_INSTALL_PREFIX}")
message(STATUS " ↳ Build        → ${CMAKE_BUILD_TYPE}")
feature_summary(DESCRIPTION
    "--------        LibVMI package summary       --------"
    WHAT PACKAGES_FOUND PACKAGES_NOT_FOUND)

feature_summary(DESCRIPTION
    "--------        LibVMI feature summary       --------"
    WHAT ENABLED_FEATURES DISABLED_FEATURES)

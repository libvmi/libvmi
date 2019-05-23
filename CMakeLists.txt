cmake_minimum_required(VERSION 3.1)

# set cmake module path, to search in cmake/modules first
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")
#-----------------------------------------------------------------------------
#                           GENERAL CONFIGURATION
#-----------------------------------------------------------------------------
project(LibVMI VERSION 0.13.0 LANGUAGES C ASM)
set(VERSION "0.13.0")
#-----------------------------------------------------------------------------
#                              DEPENDENCIES
#-----------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)
# cleanup GLIB_LDFLAGS (remove -l prefix)
string(REGEX REPLACE "-l" "" GLIB_LDFLAGS ${GLIB_LDFLAGS})

find_package(LibvmiRequest)
find_package(Xen)
find_package(Xenstore)
include(DetectArchitecture)
include(StaticAnalysis)
include(GNUInstallDirs)
#-----------------------------------------------------------------------------
#                           BUILD TYPES & FLAGS
#-----------------------------------------------------------------------------
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Werror -O2")

# strip library in release mode
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "-s")
#-----------------------------------------------------------------------------
#                             BUILD OPTIONS
#-----------------------------------------------------------------------------
option(ENABLE_XEN "Build Xen driver" ON)
option(ENABLE_KVM "Build KVM driver" ON)
option(ENABLE_BAREFLANK "Build Bareflank driver" ON)
option(ENABLE_FILE "Build file driver" ON)

option(ENABLE_WINDOWS "Build Windows introspection" ON)
option(ENABLE_LINUX "Build Linux introspection" ON)
option(ENABLE_FREEBSD "Build FreeBSD introspection" ON)

option(ENABLE_STATIC "Build libvmi static library" ON)

option(ENABLE_XENSTORE "Build with Xenstore" ON)
option(ENABLE_VMIFS "Enable vmifs: maps memory to a file through FUSE" OFF)
option(ENABLE_CONFIGFILE "Enable config file" ON)
option(ENABLE_ADDRESS_CACHE "Enable address cache" ON)
option(ENABLE_PAGE_CACHE "Enable page cache" ON)
option(REKALL_PROFILES "Use Rekall's JSON profiles" ON)
option(ENABLE_SAFETY_CHECKS "Enable API safety checks" ON)
option(ENABLE_TESTING "Build libvmi test suite" OFF)
option(BUILD_EXAMPLES "Build the examples" ON)
# See libvmi/debug.h for possible debug levels
option(VMI_DEBUG "Debug output level" OFF)

# default values
set(MAX_PAGE_CACHE_SIZE "512")
#-----------------------------------------------------------------------------
#                               SOURCES
#-----------------------------------------------------------------------------
configure_file(libvmi.pc.in ${PROJECT_BINARY_DIR}/libvmi.pc)
install(FILES ${PROJECT_BINARY_DIR}/libvmi.pc DESTINATION
    "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig")

configure_file(libvmi/config.h.in ${PROJECT_BINARY_DIR}/config.h)
# include <libvmi/libvmi.h> "config.h", "private.h" and <glib.h>
include_directories(${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR} libvmi ${GLIB_INCLUDE_DIRS})
add_definitions(-DHAVE_CONFIG_H)
add_subdirectory(libvmi)
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
message(STATUS " ↳ Compiler     → ${CMAKE_C_COMPILER}")
message(STATUS " ↳ C Flags      → ${CMAKE_C_FLAGS}")
message(STATUS " ↳ Prefix       → ${CMAKE_INSTALL_PREFIX}")
message(STATUS " ↳ Build        → ${CMAKE_BUILD_TYPE}")

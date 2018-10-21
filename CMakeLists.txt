cmake_minimum_required(VERSION 2.8)

# set cmake module path, to search in cmake/modules first
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")
#-----------------------------------------------------------------------------
#                               MODULES
#-----------------------------------------------------------------------------
# include(static_analysis)
# include(doxygen)
# include(ccache)
#-----------------------------------------------------------------------------
#                           GENERAL CONFIGURATION
#-----------------------------------------------------------------------------
project(LibVMI C)
#-----------------------------------------------------------------------------
#                              DEPENDENCIES
#-----------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)

find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)
find_package(JSON-C REQUIRED)
#-----------------------------------------------------------------------------
#                           BUILD TYPES & FLAGS
#-----------------------------------------------------------------------------
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fdiagnostics-color")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Werror -O2")

# strip binary in release mode
if(CMAKE_BUILD_TYPE MATCHES "RELEASE")
    set(CMAKE_EXE_LINKER_FLAGS "-s")
endif()
#-----------------------------------------------------------------------------
#                             BUILD OPTIONS
#-----------------------------------------------------------------------------
option(DRIVER_XEN "Build Xen driver" ON)
option(DRIVER_KVM "Build KVM driver" ON)
option(DRIVER_FILE "Build file driver" ON)

option(ENABLE_WINDOWS "Build Windows introspection" ON)
option(ENABLE_LINUX "Build Linux introspection" ON)
option(ENABLE_FREEBSD "Build FreeBSD introspection" ON)
option(BUILD_EXAMPLES "Build the examples" ON)
#-----------------------------------------------------------------------------
#                               SOURCES
#-----------------------------------------------------------------------------
configure_file(libvmi/config.h.in ${PROJECT_BINARY_DIR}/config.h)
include_directories(${PROJECT_BINARY_DIR})
# include <libvmi/libvmi.h>
include_directories(${PROJECT_SOURCE_DIR})
# include "private.h"
include_directories(libvmi)
add_subdirectory(libvmi)
if (BUILD_EXAMPLES)
    add_subdirectory(examples)
endif (BUILD_EXAMPLES)
#-----------------------------------------------------------------------------
#                               BUILD SUMMARY
#-----------------------------------------------------------------------------
message(STATUS " ↳ Compiler     → ${CMAKE_C_COMPILER}")
message(STATUS " ↳ C Flags      → ${CMAKE_C_FLAGS}")
message(STATUS " ↳ Sanitizers   → ${COMPILER_SANITIZER}")
message(STATUS " ↳ Prefix       → ${CMAKE_INSTALL_PREFIX}")
message(STATUS " ↳ Build        → ${CMAKE_BUILD_TYPE}")

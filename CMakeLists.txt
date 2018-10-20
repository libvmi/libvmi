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
include_directories (${GLIB_INCLUDE_DIRS})

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
option(BUILD_EXAMPLES "Build the examples" ON)
#-----------------------------------------------------------------------------
#                               SOURCES
#-----------------------------------------------------------------------------
include_directories(libvmi)
add_subdirectory(libvmi)
#-----------------------------------------------------------------------------
#                               BUILD SUMMARY
#-----------------------------------------------------------------------------
message(STATUS " ↳ Compiler     → ${CMAKE_C_COMPILER}")
message(STATUS " ↳ C Flags      → ${CMAKE_C_FLAGS}")
message(STATUS " ↳ Sanitizers   → ${COMPILER_SANITIZER}")
message(STATUS " ↳ Prefix       → ${CMAKE_INSTALL_PREFIX}")
message(STATUS " ↳ Build        → ${CMAKE_BUILD_TYPE}")


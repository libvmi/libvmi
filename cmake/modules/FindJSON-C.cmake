# JSON-C_FOUND - true if library and headers were found
# JSON-C_INCLUDE_DIRS - include directories
# JSON-C_LIBRARIES - library directories
# credits: https://github.com/cloudshark/cshark/blob/master/build/modules/FindJSON-C.cmake

find_package(PkgConfig)
pkg_check_modules(PC_JSON-C QUIET json-c)

find_path(JSON-C_INCLUDE_DIR json.h
	HINTS ${PC_JSON-C_INCLUDEDIR} ${PC_JSON-C_INCLUDE_DIRS} PATH_SUFFIXES json-c json)

find_library(JSON-C_LIBRARY NAMES json-c libjson-c
	HINTS ${PC_JSON-C_LIBDIR} ${PC_JSON-C_LIBRARY_DIRS})

set(JSON-C_LIBRARIES ${PC_JSON-C_LIBRARIES})
set(JSON-C_INCLUDE_DIRS ${JSON-C_INCLUDE_DIR})
set(JSON-C_VERSION ${PC_JSON-C_VERSION})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(JSON-C DEFAULT_MSG JSON-C_LIBRARY JSON-C_INCLUDE_DIR)

mark_as_advanced(JSON-C_INCLUDE_DIR JSON-C_LIBRARY JSON-C_VERSION)

set_package_properties(JSON-C PROPERTIES
    DESCRIPTION "JSON parsing library for C"
    URL "https://github.com/json-c/json-c"
    TYPE OPTIONAL)

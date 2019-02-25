# Try to find Xen headers
# Xen_FOUND
# Xen_INCLUDE_DIRS

# define HAVE_XXX
include(CheckIncludeFile)
check_include_file(xenctrl.h HAVE_XENCTRL_H)
check_include_file(xen/io/ring.h HAVE_XEN_IO_RING_H)

include(CheckTypeSize)
set(CMAKE_EXTRA_INCLUDE_FILES xenctrl.h xen/hvm/save.h)
check_type_size("hvmmem_access_t" HVMMEM_ACCESS_T)
set(CMAKE_EXTRA_INCLUDE_FILES xenctrl.h xen/memory.h)
check_type_size("xenmem_access_t" XENMEM_ACCESS_T)

find_path(Xen_INCLUDE_DIR
    NAMES xenctrl.h xen/io/ring.h)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Xen
    DEFAULT_MSG
    Xen_INCLUDE_DIR)

if (Xen_FOUND)
    set(Xen_INCLUDE_DIRS ${Xen_INCLUDE_DIR})
endif ()

mark_as_advanced(Xen_INCLUDE_DIR)

set_package_properties(Xen PROPERTIES
    DESCRIPTION "Headers for Xen development"
    URL "https://xenproject.org"
    PURPOSE "Dependency for Xen driver"
    TYPE OPTIONAL)

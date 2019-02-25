# Try to find libvirt library
# LIBVIRT_FOUND - if libvirt is found
# LIBVIRT_INCLUDE_DIRS - libvirt include directories
# LIBVIRT_LIBRARIES - libvirt libraries

find_path(Libvirt_INCLUDE_DIR
    NAMES libvirt/libvirt.h)

find_library(Libvirt_LIBRARY
    NAMES libvirt.so.0 libvirt.so)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Libvirt
    DEFAULT_MSG
    Libvirt_LIBRARY
    Libvirt_INCLUDE_DIR)

if (Libvirt_FOUND)
    set(Libvirt_INCLUDE_DIRS ${Libvirt_INCLUDE_DIR})
    set(Libvirt_LIBRARIES ${Libvirt_LIBRARY})
endif ()

mark_as_advanced(LIBVIRT_INCLUDE_DIR LIBVIRT_LIBRARY)

set_package_properties(Libvirt PROPERTIES
    DESCRIPTION "API, daemon and tools to manage virtualization platforms"
    URL "https://libvirt.org"
    PURPOSE "Dependency for KVM driver"
    TYPE OPTIONAL)

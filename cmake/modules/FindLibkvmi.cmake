# Try to find libkvmi library
# Libkvmi_FOUND - if libvirt is found
# Libkvmi_INCLUDE_DIRS - libkvmi include directories
# Libkvmi_LIBRARIES - libkvmi libraries

find_path(Libkvmi_INCLUDE_DIR
    NAMES kvmi/libkvmi.h)

find_library(Libkvmi_LIBRARY
    NAMES libkvmi.so)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Libkvmi
    DEFAULT_MSG
    Libkvmi_LIBRARY
    Libkvmi_INCLUDE_DIR)

if (Libkvmi_FOUND)
    set(Libkvmi_INCLUDE_DIRS ${Libkvmi_INCLUDE_DIR})
    set(Libkvmi_LIBRARIES ${Libkvmi_LIBRARY})
endif ()

mark_as_advanced(Libkvmi_INCLUDE_DIR Libkvmi_LIBRARY)

set_package_properties(Libkvmi PROPERTIES
    DESCRIPTION "Wrapper over the KVMi API"
    URL "https://github.com/KVM-VMI/kvm/tree/kvmi/tools/kvm/kvmi"
    PURPOSE "Dependency for the KVM driver"
    TYPE OPTIONAL)

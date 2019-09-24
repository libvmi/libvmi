# Try to find Xen headers
# Xenstore_FOUND
# Xenstore_INCLUDE_DIRS

find_path(Xenstore_INCLUDE_DIR
    NAMES xenstore.h xs.h)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Xenstore
    DEFAULT_MSG
    Xenstore_INCLUDE_DIR)

if (Xenstore_FOUND)
    set(HAVE_XENSTORE_H ON)
    set(HAVE_XS_H ON)
    set(HAVE_LIBXENSTORE ON)
    set(Xenstore_INCLUDE_DIRS ${Xenstore_INCLUDE_DIR})
endif ()

mark_as_advanced(Xenstore_INCLUDE_DIR)

set_package_properties(Xenstore PROPERTIES
    DESCRIPTION "Headers for Xen development"
    URL "https://xenproject.org"
    PURPOSE "optional dependency for Xen driver"
    TYPE OPTIONAL)

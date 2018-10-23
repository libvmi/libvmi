# Try to find Xen headers
# Xen_FOUND
# Xen_INCLUDE_DIRS

find_path(Xen_INCLUDE_DIR
    NAMES xenctrl.h xen/io/ring.h)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Xen
    DEFAULT_MSG
    Xen_INCLUDE_DIR)

if (Xen_FOUND)
    set(HAVE_XENCTRL_H ON)
    set(HAVE_XEN_IO_RING_H ON)
    set(Xen_INCLUDE_DIRS ${Xen_INCLUDE_DIR})
endif ()

mark_as_advanced(Xen_INCLUDE_DIR)

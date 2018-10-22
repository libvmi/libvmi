# LIBVMI_REQUEST_FOUND - true if headers were found
# LIBVMI_REQUEST_INCLUDE_DIRS - true if headers were found

find_path(LIBVMI_REQUEST_INCLUDE_DIRS NAMES qemu/libvmi_request.h)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(LIBVMI_REQUEST DEFAULT_MSG LIBVMI_REQUEST_INCLUDE_DIRS)
if (LIBVMI_REQUEST_FOUND)
    set(HAVE_LIBVMI_REQUEST 1)
endif ()

mark_as_advanced(LIBVMI_REQUEST_INCLUDE_DIRS)

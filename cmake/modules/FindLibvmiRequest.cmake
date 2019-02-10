# LibvmiRequest_FOUND - true if headers were found
# LibvmiRequest_INCLUDE_DIRS - true if headers were found

find_path(LibvmiRequest_INCLUDE_DIR
    NAMES qemu/libvmi_request.h)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(LibvmiRequest
    DEFAULT_MSG
    LibvmiRequest_INCLUDE_DIR)

if (LibvmiRequest_FOUND)
    set(LibvmiRequest_INCLUDE_DIRS ${LibvmiRequest_INCLUDE_DIR})
    set(HAVE_LIBVMI_REQUEST 1)
endif ()

mark_as_advanced(LibvmiRequest_INCLUDE_DIR)

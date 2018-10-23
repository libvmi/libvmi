# Try to find Xen headers
# Xenstore_FOUND
# Xenstore_INCLUDE_DIRS

# define HAVE_XXX
include(CheckIncludeFile)
check_include_file(xenstore.h HAVE_XENSTORE_H)
check_include_file(xs.h HAVE_XS_H)

find_path(Xenstore_INCLUDE_DIR
    NAMES xenstore.h xs.h)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Xenstore
    DEFAULT_MSG
    Xenstore_INCLUDE_DIR)

if (Xenstore_FOUND)
    set(HAVE_LIBXENSTORE ON)
    set(Xenstore_INCLUDE_DIRS ${Xenstore_INCLUDE_DIR})
endif ()

mark_as_advanced(Xenstore_INCLUDE_DIR)

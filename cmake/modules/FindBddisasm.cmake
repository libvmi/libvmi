# Try to find bddisasm library

find_path(Bddisasm_INCLUDE_DIR
    NAMES bddisasm/bddisasm.h)

find_library(Bddisasm_LIBRARY
    NAMES bddisasm)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Bddisasm DEFAULT_MSG
    Bddisasm_INCLUDE_DIR Bddisasm_LIBRARY)

mark_as_advanced(Bddisasm_INCLUDE_DIR Bddisasm_LIBRARY)

set(Bddisasm_INCLUDE_DIRS ${Bddisasm_INCLUDE_DIR})
set(Bddisasm_LIBRARIES ${Bddisasm_LIBRARY})

set_package_properties(Bddisasm PROPERTIES
    DESCRIPTION "bddisasm is a fast, lightweight, x86/x64 instruction decoder"
    URL "https://github.com/bitdefender/bddisasm"
    PURPOSE "required dependency for fool-patchguard example"
    TYPE OPTIONAL)


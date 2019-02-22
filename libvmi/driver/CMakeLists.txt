if (ENABLE_FILE)
    add_subdirectory(file)
endif ()

if (ENABLE_KVM)
    add_subdirectory(kvm)
endif ()

if (ENABLE_BAREFLANK)
    if (NOT ARM32 AND NOT ARM64)
        add_subdirectory(bareflank)
    endif ()
endif ()

if (ENABLE_XEN)
    add_subdirectory(xen)
endif ()

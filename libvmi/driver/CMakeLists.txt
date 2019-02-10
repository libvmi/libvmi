if (ENABLE_FILE)
    add_subdirectory(file)
endif ()

if (ENABLE_KVM)
    add_subdirectory(kvm)
endif ()

if (ENABLE_BAREFLANK)
    add_subdirectory(bareflank)
endif ()

if (ENABLE_XEN)
    add_subdirectory(xen)
endif ()

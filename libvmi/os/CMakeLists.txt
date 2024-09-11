if (ENABLE_OSX)
    add_subdirectory(osx)
endif ()

if (ENABLE_FREEBSD)
    add_subdirectory(freebsd)
endif ()

if (ENABLE_LINUX)
    add_subdirectory(linux)
endif ()

if (ENABLE_WINDOWS)
    add_subdirectory(windows)
endif ()

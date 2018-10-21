set(windows_src
    core.c
    kdbg.c
    memory.c
    peparse.c
    process.c
    unicode.c
)

add_library(windows SHARED ${windows_src})
target_include_directories(windows PRIVATE ${GLIB_INCLUDE_DIRS})

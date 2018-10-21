set(freebsd_src
    core.c
    memory.c
    symbols.c
)

add_library(freebsd SHARED ${freebsd_src})
target_include_directories(freebsd PRIVATE ${GLIB_INCLUDE_DIRS})

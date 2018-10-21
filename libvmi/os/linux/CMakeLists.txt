set(linux_src
    core.c
    memory.c
    symbols.c
)

add_library(linux SHARED ${linux_src})
target_include_directories(linux PRIVATE ${GLIB_INCLUDE_DIRS})

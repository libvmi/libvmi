set(freebsd_src
    core.c
    memory.c
    symbols.c
)

add_library(freebsd SHARED ${freebsd_src})

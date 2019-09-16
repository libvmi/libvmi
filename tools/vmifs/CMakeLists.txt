pkg_search_module(FUSE fuse)
if (NOT FUSE_FOUND)
    message(WARNING "FUSE library missing (libfuse-dev)")
    set(ENABLE_VMIFS OFF CACHE BOOL "Enable vmifs: maps memory to a file through FUSE" FORCE)
else ()
    add_executable(vmifs vmifs.c)
    target_include_directories(vmifs PRIVATE ${FUSE_INCLUDE_DIRS})
    # cannot use ${FUSE_CFLAGS}, bug while parsing -D_FILE_OFFSET_BITS=64
    # hardcoded for now
    target_compile_definitions(vmifs PRIVATE FUSE_USE_VERSION=22 _FILE_OFFSET_BITS=64)
    target_link_libraries(vmifs vmi_shared ${FUSE_LDFLAGS})
endif ()

# generate config.h
configure_file(config.h.in ${PROJECT_BINARY_DIR}/config.h)
include_directories(${PROJECT_BINARY_DIR})

# add_subdirectory(config)

set(file_driver_src
    driver/file/file.c
)

add_library(file_driver SHARED ${file_driver_src})

set(kvm_driver_src
    driver/kvm/kvm.c
    driver/kvm/libvirt_wrapper.c
)

add_library(kvm_driver SHARED ${kvm_driver_src})
target_link_libraries(kvm_driver ${CMAKE_DL_LIBS} ${JSON-C_LIBRARIES})

# set(xen_driver_src
#     driver/xen/altp2m.c
#     driver/xen/altp2m_private.h
#     driver/xen/xen.h
#     driver/xen/xen_private.h
#     driver/xen/xen.c
#     driver/xen/xen_events.c
#     driver/xen/xen_events.h
#     driver/xen/xen_events_private.h
#     driver/xen/xen_events_46.c
#     driver/xen/xen_events_48.c
#     driver/xen/xen_events_legacy.c
#     driver/xen/libxc_wrapper.c
#     driver/xen/libxc_wrapper.h
#     driver/xen/libxs_wrapper.c
#     driver/xen/libxs_wrapper.h
# )
# 
# add_library(xen_driver SHARED ${xen_driver_src})
# target_include_directories(xen_driver PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

set(windows_src
    os/windows/core.c
    os/windows/kdbg.c
    os/windows/memory.c
    os/windows/peparse.c
    os/windows/process.c
    os/windows/unicode.c
)

set(linux_src
    os/linux/core.c
    os/linux/memory.c
    os/linux/symbols.c
)

set(freebsd_src
    os/freebsd/core.c
    os/freebsd/memory.c
    os/freebsd/symbols.c
)

set(libvmi_src
    accessors.c
    convenience.c
    core.c
    events.c
    performance.c
    pretty_print.c
    read.c
    slat.c
    strmatch.c
    write.c
    memory.c
    shm.c
    arch/arch_interface.c
    arch/intel.c
    arch/amd64.c
    arch/arm_aarch32.c
    arch/arm_aarch64.c
    driver/driver_interface.c
    driver/memory_cache.c
    os/os_interface.c
)

add_library(vmi SHARED
    ${windows_src}
    ${linux_src}
    ${freebsd_src}
    ${libvmi_src}
)

target_link_libraries(vmi
    ${GLIB_LDFLAGS}
    m
    file_driver
    kvm_driver
)

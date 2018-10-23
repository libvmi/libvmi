set(xen_driver_src
    altp2m.c
    altp2m_private.h
    xen.h
    xen_private.h
    xen.c
    xen_events.c
    xen_events.h
    xen_events_private.h
    xen_events_46.c
    xen_events_48.c
    xen_events_legacy.c
    libxc_wrapper.c
    libxc_wrapper.h
    libxs_wrapper.c
    libxs_wrapper.h
)

add_library(xen_driver SHARED ${xen_driver_src})
target_include_directories(xen_driver PRIVATE ${GLIB_INCLUDE_DIRS})
# CMAKE_DL_LIBS -> dlopen* lib
target_link_libraries(xen_driver ${CMAKE_DL_LIBS})

target_sources(vmi_shared PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/altp2m.c
    ${CMAKE_CURRENT_SOURCE_DIR}/altp2m_private.h
    ${CMAKE_CURRENT_SOURCE_DIR}/xen.h
    ${CMAKE_CURRENT_SOURCE_DIR}/xen_private.h
    ${CMAKE_CURRENT_SOURCE_DIR}/xen.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xen_events.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xen_events.h
    ${CMAKE_CURRENT_SOURCE_DIR}/xen_events_private.h
    ${CMAKE_CURRENT_SOURCE_DIR}/libxc_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/libxc_wrapper.h
    ${CMAKE_CURRENT_SOURCE_DIR}/libxs_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/libxs_wrapper.h
)

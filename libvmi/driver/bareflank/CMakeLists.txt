target_sources(vmi_shared PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/bareflank.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hypercall.S
)

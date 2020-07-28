target_sources(vmi_shared PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/bareflank.c
)

add_subdirectory(bfsdk)

target_sources(vmi_shared PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/intrinsics.S
)

target_include_directories(vmi_shared PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

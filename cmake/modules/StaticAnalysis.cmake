# detect ccc_analyzer
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/static_analysis_build)
# create custom target
add_custom_target(
    static_analysis
    COMMAND scan-build cmake -DCMAKE_BUILD_TYPE=DEBUG ${PROJECT_SOURCE_DIR}
    # -v -> verbosity
    # -V -> open results in browser
    COMMAND scan-build -v -V make
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/static_analysis_build)

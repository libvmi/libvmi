# detect ccc_analyzer
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/static_analysis_build)
# create custom target
add_custom_target(
    static_analysis
    COMMAND scan-build cmake -DCMAKE_BUILD_TYPE=DEBUG -DENABLE_CONFIGFILE=OFF ${PROJECT_SOURCE_DIR}
    # -v -> verbosity
    # -V -> open results in browser
    COMMAND scan-build -v -V make
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/static_analysis_build)

# create custom target
# we don't need to analyze examples or test suite code
add_custom_target(
    static_analysis_test
    COMMAND scan-build cmake -DCMAKE_BUILD_TYPE=DEBUG -DBUILD_EXAMPLES=OFF
        -DENABLE_TESTING=OFF -DENABLE_CONFIGFILE=OFF ${PROJECT_SOURCE_DIR}
    # -v -> verbosity
    COMMAND scan-build -v --status-bugs make
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/static_analysis_build)

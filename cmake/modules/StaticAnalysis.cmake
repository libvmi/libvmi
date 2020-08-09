file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/static_analysis_build)

# add SCAN_BUILD var to select scan-build-x binary
# default to "scan-build"
set(SCAN_BUILD "scan-build" CACHE STRING "scan-build binary to be used for static analysis")

# create custom target
add_custom_target(
    static_analysis
    COMMAND ${SCAN_BUILD} cmake -DCMAKE_BUILD_TYPE=DEBUG -DENABLE_CONFIGFILE=OFF ${PROJECT_SOURCE_DIR}
    # -v -> verbosity
    # -V -> open results in browser
    COMMAND ${SCAN_BUILD} -v -V make
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/static_analysis_build)

# create custom target
# we don't need to analyze examples or test suite code
add_custom_target(
    static_analysis_test
    COMMAND ${SCAN_BUILD} cmake -DCMAKE_BUILD_TYPE=DEBUG -DBUILD_EXAMPLES=OFF
        -DENABLE_TESTING=OFF -DENABLE_CONFIGFILE=OFF ${PROJECT_SOURCE_DIR}
    # -v -> verbosity
    COMMAND ${SCAN_BUILD} -v --status-bugs make
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/static_analysis_build)

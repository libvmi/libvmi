find_package(Check REQUIRED)
find_package(Threads REQUIRED)
include_directories(${Check_INCLUDE_DIRS})

# compile as static libraries since libcheck.a is also static
add_library(test_accessor STATIC test_accessor.c)
target_link_libraries(test_accessor vmi_shared ${Check_LIBRARIES})

add_library(test_cache STATIC test_cache.c)
target_link_libraries(test_cache vmi_shared ${Check_LIBRARIES})

add_library(test_getvapages STATIC test_getvapages.c)
target_link_libraries(test_getvapages vmi_shared ${Check_LIBRARIES})

add_library(test_init STATIC test_init.c)
target_link_libraries(test_init vmi_shared ${Check_LIBRARIES})

add_library(test_peparse STATIC test_peparse.c)
target_link_libraries(test_peparse vmi_shared ${Check_LIBRARIES})

add_library(test_print STATIC test_print.c)
target_link_libraries(test_print vmi_shared ${Check_LIBRARIES})

add_library(test_read STATIC test_read.c)
target_link_libraries(test_read vmi_shared ${Check_LIBRARIES})

add_library(test_translate STATIC test_translate.c)
target_link_libraries(test_translate vmi_shared ${Check_LIBRARIES})

add_library(test_util STATIC test_util.c)
target_link_libraries(test_util vmi_shared ${Check_LIBRARIES})

add_library(test_write STATIC test_write.c)
target_link_libraries(test_write vmi_shared ${Check_LIBRARIES})

add_executable(check_libvmi check_runner.c)
target_compile_options(check_libvmi PRIVATE ${Check_CFLAGS})
# link with threads: workaround link issue
# https://github.com/libcheck/check/issues/48)
target_link_libraries(check_libvmi vmi_shared ${Check_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
# output in current directory
set_target_properties(check_libvmi
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(check_libvmi test_accessor)
target_link_libraries(check_libvmi test_cache)
target_link_libraries(check_libvmi test_getvapages)
target_link_libraries(check_libvmi test_init)
target_link_libraries(check_libvmi test_peparse)
target_link_libraries(check_libvmi test_print)
target_link_libraries(check_libvmi test_read)
target_link_libraries(check_libvmi test_translate)
target_link_libraries(check_libvmi test_util)
target_link_libraries(check_libvmi test_write)

# tests
add_test(NAME test_libvmi
    COMMAND check_libvmi)

# add "check" target, to keep autotools compatibility
# Note: "check" is already used by CMake as a Utility target,
# we cannot use it
add_custom_target(
    check_integration
    COMMAND make test
    COMMAND vmi-process-list $ENV{LIBVMI_CHECK_TESTVM}
    COMMAND vmi-module-list $ENV{LIBVMI_CHECK_TESTVM}
    DEPENDS check_libvmi vmi-process-list vmi-module-list
    VERBATIM
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

set(file_driver_src
    file.c
)

add_library(file_driver SHARED ${file_driver_src})
target_include_directories(file_driver PRIVATE ${GLIB_INCLUDE_DIRS})

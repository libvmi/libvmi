find_package(JSON-C REQUIRED)
find_package(Libvirt REQUIRED)

set(kvm_driver_src
    kvm.c
    libvirt_wrapper.c
)

add_library(kvm_driver SHARED ${kvm_driver_src})
target_include_directories(kvm_driver PRIVATE ${JSON-C_INCLUDE_DIRS})
# CMAKE_DL_LIBS -> dlopen* lib
target_link_libraries(kvm_driver ${CMAKE_DL_LIBS} ${JSON-C_LIBRARIES})

if (ENABLE_SHM_SNAPSHOT)
    # shm_open/shm_unlink are provided by -lrt
    target_link_libraries(kvm_driver rt)
endif ()

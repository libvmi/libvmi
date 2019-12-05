target_sources(vmi_shared PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/kvm_common.c
        ${CMAKE_CURRENT_SOURCE_DIR}/libvirt_wrapper.c)

if (ENABLE_KVM_LEGACY)
    target_sources(vmi_shared PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/kvm_legacy.c)
else ()
    # include libkvmi headers
    target_include_directories(vmi_shared PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include)

    target_sources(vmi_shared PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/kvm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/kvm_events.c
        ${CMAKE_CURRENT_SOURCE_DIR}/libkvmi.c)
endif ()

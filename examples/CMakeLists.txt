add_executable(map-addr map-addr.c)
target_link_libraries(map-addr vmi_shared)

add_executable(map-symbol map-symbol.c)
target_link_libraries(map-symbol vmi_shared)

add_executable(va-pages va-pages.c)
target_link_libraries(va-pages vmi_shared)

add_executable(event-example event-example.c)
target_link_libraries(event-example vmi_shared)

add_executable(interrupt-event-example interrupt-event-example.c)
target_link_libraries(interrupt-event-example vmi_shared)

add_executable(breakpoint-emulate-example breakpoint-emulate-example.c)
target_link_libraries(breakpoint-emulate-example vmi_shared)

add_executable(wait-for-domain-example wait-for-domain-example.c)
target_link_libraries(wait-for-domain-example vmi_shared)

add_executable(msr-event-example msr-event-example.c)
target_link_libraries(msr-event-example vmi_shared)

add_executable(singlestep-event-example singlestep-event-example.c)
target_link_libraries(singlestep-event-example vmi_shared)

add_executable(step-event-example step-event-example.c)
target_link_libraries(step-event-example vmi_shared)

add_executable(xen-emulate-reponse xen-emulate-response.c)
target_link_libraries(xen-emulate-reponse vmi_shared)

add_executable(vmi-process-list process-list.c)
target_link_libraries(vmi-process-list vmi_shared)

add_executable(vmi-dump-memory dump-memory.c)
target_link_libraries(vmi-dump-memory vmi_shared)

add_executable(vmi-module-list module-list.c)
target_link_libraries(vmi-module-list vmi_shared)

if (ENABLE_WINDOWS)
    add_executable(vmi-win-guid win-guid.c)
    target_link_libraries(vmi-win-guid vmi_shared)

    add_executable(vmi-win-offsets win-offsets.c)
    target_link_libraries(vmi-win-offsets vmi_shared)

    find_package(JSON-C)
    set_package_properties(JSON-C PROPERTIES
      PURPOSE "Dependency for win-proc-stat example")
    if (NOT JSON-C_FOUND)
      message(WARNING "Cannot find JSON: disabling win-proc-stat example")
    else ()
      message(INFO "Build win-proc-stat: ${JSON-C_LIBRARIES}; ${JSON-C_INCLUDE_DIRS}")
      add_executable(vmi-win-proc-stat win-proc-stat.c)
      target_link_libraries(vmi-win-proc-stat vmi_shared ${JSON-C_LIBRARIES})
      target_include_directories(vmi-win-proc-stat PRIVATE ${JSON-C_INCLUDE_DIRS})
    endif ()
endif ()

install(TARGETS
    vmi-process-list
    vmi-module-list
    vmi-dump-memory
    DESTINATION bin)

if (ENABLE_WINDOWS)
    install(TARGETS
        vmi-win-guid
        vmi-win-offsets
        DESTINATION bin)
endif ()

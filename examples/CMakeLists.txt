add_executable(map-addr map-addr.c)
target_link_libraries(map-addr vmi)

add_executable(map-symbol map-symbol.c)
target_link_libraries(map-symbol vmi)

add_executable(shm-snapshot-process-list shm-snapshot-process-list.c)
target_link_libraries(shm-snapshot-process-list vmi)

add_executable(va-pages va-pages.c)
target_link_libraries(va-pages vmi)

add_executable(event-example event-example.c)
target_link_libraries(event-example vmi)

add_executable(interrupt-event-example interrupt-event-example.c)
target_link_libraries(interrupt-event-example vmi)

add_executable(msr-event-example msr-event-example.c)
target_link_libraries(msr-event-example vmi)

add_executable(singlestep-event-example singlestep-event-example.c)
target_link_libraries(singlestep-event-example vmi)

add_executable(step-event-example step-event-example.c)
target_link_libraries(step-event-example vmi)

add_executable(xen-emulate-reponse xen-emulate-response.c)
target_link_libraries(xen-emulate-reponse vmi)

add_executable(vmi-process-list process-list.c)
target_link_libraries(vmi-process-list vmi)

add_executable(vmi-dump-memory dump-memory.c)
target_link_libraries(vmi-dump-memory vmi)

add_executable(vmi-module-list module-list.c)
target_link_libraries(vmi-module-list vmi)

add_executable(vmi-win-guid win-guid.c)
target_link_libraries(vmi-win-guid vmi)

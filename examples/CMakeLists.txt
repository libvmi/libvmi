add_executable(map-addr map-addr.c)
target_link_libraries(map-addr vmi)

add_executable(map-symbol map-symbol.c)
target_link_libraries(map-symbol vmi)

add_executable(shm-snapshot-process-list shm-snapshot-process-list.c)
target_link_libraries(shm-snapshot-process-list vmi)

add_executable(va-pages va-pages.c)
target_link_libraries(va-pages vmi)

add_executable(vmi-dump-memory dump-memory.c)
target_link_libraries(vmi-dump-memory vmi)

add_executable(vmi-module-list module-list.c)
target_link_libraries(vmi-module-list vmi)

add_executable(vmi-win-guid win-guid.c)
target_link_libraries(vmi-win-guid vmi)

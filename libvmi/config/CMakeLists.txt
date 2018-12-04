if (ENABLE_CONFIGFILE)
    ADD_CUSTOM_COMMAND(
        OUTPUT scanner.c
        COMMAND ${FLEX_EXECUTABLE}
            --outfile=${CMAKE_CURRENT_BINARY_DIR}/scanner.c
            ${CMAKE_CURRENT_SOURCE_DIR}/lexicon.l
        COMMENT "Generating scanner.c"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    ADD_CUSTOM_COMMAND(
        OUTPUT parser.c
        COMMAND ${BISON_EXECUTABLE}
            --output=${CMAKE_CURRENT_BINARY_DIR}/parser.c
            --defines=${CMAKE_CURRENT_BINARY_DIR}/grammar.h
            ${CMAKE_CURRENT_SOURCE_DIR}/grammar.y
        COMMENT "Generating parser.c"
    )

    target_sources(vmi_shared PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
        ${CMAKE_CURRENT_BINARY_DIR}/parser.c
    )
    target_include_directories(vmi_shared PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR} # grammar.h
        ${CMAKE_CURRENT_SOURCE_DIR} # config_parser.h
    )
endif ()

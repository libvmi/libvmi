find_package(Doxygen)
if(DOXYGEN_FOUND)
    configure_file(
        doxyfile.in
        "${CMAKE_CURRENT_BINARY_DIR}/doxyfile"
    )
    add_custom_target(
        doc
        COMMAND doxygen ${CMAKE_CURRENT_BINARY_DIR}/doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT Doxygen is generating the documentation...
        VERBATIM
    )
else(DOXYGEN_FOUND)
    message(WARNING "Doxygen not found. Target doc will not be available")
endif(DOXYGEN_FOUND)

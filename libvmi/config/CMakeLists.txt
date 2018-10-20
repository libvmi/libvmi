ADD_CUSTOM_COMMAND(
    OUTPUT scanner.c
    COMMAND ${FLEX_EXECUTABLE}
        --outfile=scanner.c
        lexicon.l
    COMMENT "Generating scanner.c"
)

ADD_CUSTOM_COMMAND(
    OUTPUT parser.c
    COMMAND ${BISON_EXECUTABLE}
        --output=parser.c
        grammar.y
    COMMENT "Generating parser.c"
)

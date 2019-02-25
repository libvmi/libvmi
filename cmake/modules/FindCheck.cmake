find_package(PkgConfig)
pkg_check_modules(Check REQUIRED check)

set_package_properties(Check PROPERTIES
    DESCRIPTION "Unit test framework for C"
    URL "https://libcheck.github.io/check/"
    PURPOSE "Dependency for LibVMI test suite"
    TYPE RECOMMENDED)

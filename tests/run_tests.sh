#!/bin/bash

function error_exit
{
    cat tests/test-suite.log
    sudo make clean
    exit 1
}

export LIBVMI_CHECK_TESTVM=$1

# build code
sudo make clean || error_exit
make || error_exit

# run unit tests
sudo LIBVMI_CHECK_TESTVM=$1 make check || error_exit

# poor man's integration tests
sudo LIBVMI_CHECK_TESTVM=$LIBVMI_CHECK_TESTVM ./examples/vmi-process-list $LIBVMI_CHECK_TESTVM || error_exit
sudo LIBVMI_CHECK_TESTVM=$LIBVMI_CHECK_TESTVM ./examples/vmi-module-list $LIBVMI_CHECK_TESTVM || error_exit

exit 0

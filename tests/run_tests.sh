#!/bin/bash

function error_exit
{
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
sudo LIBVMI_CHECK_TESTVM=$LIBVMI_CHECK_TESTVM ./examples/process-list $LIBVMI_CHECK_TESTVM || error_exit
sudo LIBVMI_CHECK_TESTVM=$LIBVMI_CHECK_TESTVM ./examples/module-list $LIBVMI_CHECK_TESTVM || error_exit

exit 0

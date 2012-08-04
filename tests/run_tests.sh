#!/bin/sh

export LIBVMI_CHECK_TESTVM=$1

# unit tests
sudo make check

# poor man's integration tests
sudo ./examples/process-list $LIBVMI_CHECK_TESTVM
sudo ./examples/module-list $LIBVMI_CHECK_TESTVM

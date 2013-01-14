#!/bin/sh

LIBTOOLIZE=`which libtoolize`
if [ "$?" -eq 1 ] ; then
    LIBTOOLIZE=`which glibtoolize`
fi
if [ "$?" -eq 1 ] ; then
    echo "Error: could not find libtoolize or glibtoolize"
    return 1
fi

set -e

$LIBTOOLIZE --force --copy
aclocal
autoheader
automake -a
autoconf

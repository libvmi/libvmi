#!/bin/sh

libtoolize --force --copy
aclocal
autoheader
automake -a
autoconf

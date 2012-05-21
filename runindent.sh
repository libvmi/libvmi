#!/bin/sh

INDENT=/usr/bin/indent

for file in `find . -iname '*.c' -print | grep -v 'libvmi/config'`
do
    $INDENT $file
done

for file in `find . -iname '*.h' -print | grep -v 'libvmi/config'`
do
    $INDENT $file
done

#!/usr/bin/env python

from __future__ import with_statement

with open('kpcr.c', 'r') as f:
    inside = 0
    for line in f:
        if line.startswith('struct _KDDEBUGGER_DATA64'):
            inside = 1
        elif inside and line.startswith('} __attribute__ ((packed));'):
            inside = 0
        elif inside and line.startswith('    uint64_t'):
            fields = line.split()
            fields = fields[1].split(';')
            varname = fields[0]
            print """    else if (strncmp(symbol, "%s", max_symbol_length) == 0){
        *offset = (unsigned long)(&(d.%s)) - (unsigned long)(&d);
    }""" % (varname, varname)

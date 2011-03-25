#!/usr/bin/env python

from distutils.core import setup, Extension

pyvmimod = Extension('pyvmi', sources=['pyvmi.c'],
                    include_dirs = ['/usr/local/include'],
                    library_dirs = ['/usr/local/lib'],
                    libraries = ['vmi'])


setup(name='PyVmi', version='1.0',
      description = 'Python interface to LibVMI',
      ext_modules = [pyvmimod])

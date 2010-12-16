#!/usr/bin/env python

from distutils.core import setup, Extension

pyxamod = Extension('pyxa', sources=['pyxamodule.c'],
                    include_dirs = ['/usr/local/include'],
                    library_dirs = ['/usr/local/lib'],
                    libraries = ['xenaccess'])


setup(name='PyXa', version='1.0',
      description = 'Python interface to XenAccess',
      ext_modules = [pyxamod])

#!/usr/bin/env python
"""
PyVMI is a python language wrapper for the LibVMI Library. The LibVMI Library
is an introspection library that simplifies access to memory in a target
virtual machine or in a file containing a dump of a system's physical memory.

Author: Bryan D. Payne (bdpayne@acm.org)

Copyright 2014 Bryan D. Payne

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
import pyvmi
from setuptools import setup

try:
    import pyvmi.interface
except ImportError:
    # installing - there is no cffi yet
    ext_modules = []
else:
    # building bdist - cffi is here!
    ext_modules = [pyvmi.interface.ffi.verifier.get_extension()]


setup(
    name=pyvmi.__title__,
    version=pyvmi.__version__,

    description=pyvmi.__summary__,
    long_description=open('README').read(),
    url=pyvmi.__uri__,
    license=pyvmi.__license__,

    author=pyvmi.__author__,
    author_email=pyvmi.__email__,

    setup_requires=[
        'cffi',
    ],
    install_requires=[
        'cffi',
    ],
    extras_require={
        'tests': [
            'pep8',
            'pylint',
            'pytest',
        ],
    },
    tests_require=[
        'pytest',
    ],

    packages=[
        'pyvmi',
    ],

    package_data={
        'pyvmi': [
            'interface.h'
        ]
    },

    ext_package='pyvmi',
    ext_modules=ext_modules,

    zip_safe=False,
)

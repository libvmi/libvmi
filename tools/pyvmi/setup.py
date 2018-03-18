#!/usr/bin/env python3


from setuptools import setup


setup(
    name='libvmi',
    version='3.0',
    description='Python interface to LibVMI',
    setup_requires=["cffi>=1.6.0", "pkgconfig"],
    install_requires=["cffi>=1.6.0", "six"],
    cffi_modules=['libvmi/glib_build.py:ffi', 'libvmi/libvmi_build.py:ffi'],
    packages=['libvmi'],
    package_data={
        'libvmi': ['*_cdef.h']
    }
)

#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Ryan<dawnsun@sina.com>
# Created on 2021-05-21


from setuptools import setup, find_packages

setup(name = "frida-hooks",
    version = "0.9.15",
    description = "Dynamic instrumentation toolkits powered by Frida",
    author = "Ryan",
    author_email = "dawnsun@sina.com",
    url = "https://github.com/softice70/frida-hooks",
    packages = find_packages(),
    license='Apache License, Version 2.0',
    entry_points = {
                   'console_scripts': ['frida-hooks=frida_hooks.main:main']
               },
    package_data={
      'frida_hooks': [
          'scripts.js',
          'bin/*.*'
      ],
    },
)

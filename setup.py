#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# Copyright (c) 2012 Bastian Kleineidam

from setuptools import setup
from distutils.command.register import register

appname = 'python-keepass'
version = '0.2'
description = "Command line interface for KeePass v4 files."
long_description = """
A command line interface to read from file in KeePass format v4
(used by KeePass and KeePassx 2.x).
"""


class MyRegister (register, object):
    """Custom register command."""

    def build_post_data(self, action):
        """Force application name to lower case."""
        data = super(MyRegister, self).build_post_data(action)
        data['name'] = data['name'].lower()
        return data


args = dict(
    name = appname,
    version = version,
    url = 'https://github.com/wummel/python-keepass',
    license = 'GPL',
    description = description,
    long_description = long_description,
    maintainer = 'Bastian Kleineidam',
    maintainer_email = 'bastian.kleineidam@web.de',
    packages = ['keepasslib'],
    scripts = ['keepassc'],
    data_files = [],
    cmdclass = {
        'register': MyRegister,
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Intended Audience :: End Users/Desktop',
        'Environment :: Console',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities'
    ],
)

setup(**args)

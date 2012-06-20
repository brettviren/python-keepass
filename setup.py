#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# Copyright (c) 2012 Bastian Kleineidam

import sys
import glob
import os
try:
    # setuptools (which is needed by py2app) monkey-patches the
    # distutils.core.Command class.
    # So we need to import it before importing the distutils core
    import setuptools
except ImportError:
    # ignore when setuptools is not installed
    pass
from distutils.core import setup
from distutils.command.register import register
from distutils import util
try:
    import py2exe
except ImportError:
    # ignore when py2exe is not installed
    pass

appname = 'python-keepass'
version = '0.2'
description = "Command line and python interface for KeePass v3 files."
long_description = """
A command line and Python interface for operating on
files in KeePass format v3 (used by KeePass 1.x, and KeePassX).
"""

# basic excludes for py2exe
py_excludes = ['doctest', 'unittest', 'optcomplete', 'Tkinter']
# py2exe options for windows .exe packaging
py2exe_options = dict(
    packages=["encodings"],
    excludes=py_excludes + ['win32com.gen_py'],
    # silence py2exe error about not finding msvcp90.dll
    dll_excludes=['MSVCP90.dll'],
    compressed=1,
    optimize=2,
)
# py2app options for OSX packaging
py2app_options = dict(
    excludes=py_excludes,
    strip=True,
    optimize=2,
    argv_emulation=False,
)


def get_nt_platform_vars ():
    """Return program file path and architecture for NT systems."""
    platform = util.get_platform()
    if platform == "win-amd64":
        # the Visual C++ runtime files are installed in the x86 directory
        progvar = "%ProgramFiles(x86)%"
        architecture = "amd64"
    elif platform == "win32":
        progvar = "%ProgramFiles%"
        architecture = "x86"
    else:
        raise ValueError("Unsupported platform %r" % platform)
    return os.path.expandvars(progvar), architecture


def add_msvc_files (files):
    """Add needed MSVC++ runtime files."""
    dirname = "Microsoft.VC90.CRT"
    prog_dir, architecture = get_nt_platform_vars()
    p = r'%s\Microsoft Visual Studio 9.0\VC\redist\%s\%s\*.*'
    args = (prog_dir, architecture, dirname)
    files.append((dirname, glob.glob(p % args)))


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
    maintainer_email = 'calvin@users.sourceforge.net',
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
    options = {
        "py2exe": py2exe_options,
        "py2app": py2app_options,
    }
)

if 'py2exe' in sys.argv[1:]:
    add_msvc_files(args['data_files'])
    args['console'] = ['keepassc']
if sys.platform == 'darwin':
    args["app"] = ['keepassc']

setup(**args)

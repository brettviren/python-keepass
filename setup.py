from setuptools import setup
from os.path import join, dirname
import sys

sys.path.append("python")

import keepass as module
setup(
    name ='keepass',
    version = module.__version__,
    author = module.__author__,
    author_email = module.__email__,
    description = module.__description__,
    license = module.__license__,
    keywords = module.__keywords__,
    url = module.__url__,   # project home page, if any
    long_description=open(join(dirname(__file__), 'README.txt')).read(),
    package_dir={'': 'python'},
    packages=['keepass'],
    scripts=[
        'keepassc.py',
    ],
    install_requires=[
        'pycrypto',
        'six',
    ],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    tests_require=[
        'nose',
    ],
    test_suite='nose.collector',
)

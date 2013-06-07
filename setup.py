from setuptools import setup

setup(
    name='KeePass',
    version='1.0',
    description='Command line and Python interfaces for operating on files in KeePass .kdb format',
    package_dir={'': 'python'},
    packages=['keepass'],
    install_requires=[
        'pycrypto',
    ],
)

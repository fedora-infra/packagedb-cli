#!/usr/bin/env python
"""
Setup script
"""

from setuptools import setup

from pkgdb2client import __version__

setup(
    name='packagedb-cli',
    description='A command line tool to access the Fedora Package Database.',
    version=__version__,
    license='GPLv2+',
    download_url='https://fedorahosted.org/releases/p/a/packagedb-cli/',
    url='https://fedorahosted.org/packagedb-cli/',
    author='Pierre-Yves Chibon',
    author_email='pingou@pingoured.fr',
    py_modules=['pkgdb2client', 'pkgdb2_cli'],
    entry_points={
        'console_scripts': [
            "pkgdb-cli=pkgdb2_cli:main",
        ]
    },
    install_requires=['requests', 'python-bugzilla', 'python-fedora']
)

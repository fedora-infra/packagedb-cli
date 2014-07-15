#!/usr/bin/env python
"""
Setup script
"""

from setuptools import setup

setup(
    name='packagedb-cli',
    description='A command line tool to access the Fedora Package Database.',
    version='2.4',
    license='GPLv2+',
    download_url='https://fedorahosted.org/releases/p/a/packagedb-cli/',
    url='https://fedorahosted.org/packagedb-cli/',
    author='Pierre-Yves Chibon',
    author_email='pingou@pingoured.fr',
    py_modules=['pkgdb2client', 'pkgdb2_cli', 'pkgdb2version'],
    entry_points={
        'console_scripts': [
            "pkgdb-cli=pkgdb2_cli:main",
        ]
    },
    install_requires=[
        'requests', 'python-bugzilla', 'python-fedora', 'setuptools',
        'beautifulsoup4'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v2 or later '
        '(GPLv2+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries',
    ],
)

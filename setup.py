#!/usr/bin/env python
"""
Setup script
"""

from setuptools import setup

setup(
    name='packagedb-cli',
    description='A command line tool to access the Fedora Package Database.',
    version='2.13',
    license='GPLv2+',
    download_url='https://fedorahosted.org/releases/p/a/packagedb-cli/',
    url='https://fedorahosted.org/packagedb-cli/',
    author='Pierre-Yves Chibon',
    author_email='pingou@pingoured.fr',
    packages=['pkgdb2client'],
    entry_points={
        'console_scripts': [
            "pkgdb-cli=pkgdb2client.cli:main",
            "pkgdb-admin=pkgdb2client.admin:main",
        ]
    },
    install_requires=[
        'requests', 'python-bugzilla', 'python-fedora', 'setuptools', 'six',
        'beautifulsoup4'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
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

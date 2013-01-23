#!/usr/bin/env python
"""
Setup script
"""

from distutils.core import setup

setup(
    name = 'packagedb-cli',
    description = 'A command line tool to access the Fedora Package Database.',
    version = '1.3.0',
    license = 'GPLv2+',
    download_url = 'https://fedorahosted.org/releases/p/a/packagedb-cli/',
    url = 'https://fedorahosted.org/packagedb-cli/',
    scripts=['pkgdb-cli'],
	author='Pierre-Yves Chibon',
	author_email='pingou@pingoured.fr',
    )

# -*- coding: utf-8 -*-

"""
# pkgdb2 - a commandline admin frontend for the Fedora package database
#
# Copyright (C) 2014 Red Hat Inc
# Copyright (C) 2014 Pierre-Yves Chibon
# Author: Pierre-Yves Chibon <pingou@pingoured.fr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
# See http://www.gnu.org/copyleft/gpl.html  for the full text of the
# license.
"""

import getpass

from bugzilla import Bugzilla
from fedora.client import AccountSystem, AuthError

import pkgdb2client

RH_BZ_API = 'https://bugzilla.redhat.com/xmlrpc.cgi'
BZCLIENT = Bugzilla(url=RH_BZ_API)
FASCLIENT = AccountSystem('https://admin.fedoraproject.org/accounts')


def bz_login():
    ''' Login on bugzilla. '''
    print 'To keep going, we need to authenticate against bugzilla' \
        ' at {0}'.format(RH_BZ_API)
    username = raw_input("Bugzilla user: ")
    password = getpass.getpass("Bugzilla password: ")
    BZCLIENT.login(username, password)


def get_bugz(pkg_name):
    ''' Return the list of open bugs reported against a package.

    :arg pkg_name: the name of the package to look-up in bugzilla

    '''

    bugbz = BZCLIENT.query(
                {'bug_status': ['NEW', 'ASSIGNED', 'NEEDINFO'],
                 'component': pkg_name})

    return bugbz

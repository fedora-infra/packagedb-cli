# -*- coding: utf-8 -*-

"""
# pkgdb2 - a commandline admin frontend for the Fedora package database
#
# Copyright (C) 2014-2015 Red Hat Inc
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
import json
import os
import tempfile

from datetime import datetime

import requests
import fedora_cert

from bugzilla import Bugzilla
from fedora.client import AccountSystem, AuthError

import pkgdb2client

try:
    USERNAME = fedora_cert.read_user_cert()
except fedora_cert.fedora_cert_error:
    pkgdb2client.LOG.debug('Could not read Fedora cert, asking for username')
    USERNAME = None

RH_BZ_API = 'https://bugzilla.redhat.com/xmlrpc.cgi'
BZCLIENT = Bugzilla(url=RH_BZ_API)
FASCLIENT = AccountSystem(
    'https://admin.fedoraproject.org/accounts',
    username=USERNAME)


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
         'component': pkg_name}
    )

    return bugbz


def get_bug(bugid):
    ''' Return the bug with the specified identifier.

    :arg bugid: the identifier of the bug to retrieve
    :returns: the list of the people (their email address) that commented
        on the specified ticket

    '''

    bug = BZCLIENT.getbug(bugid)
    if '@' not in bug.creator:
        bz_login()
        bug = BZCLIENT.getbug(bugid)
    return bug


def get_users_in_bug(bugid):
    ''' Return the list of open bugs reported against a package.

    :arg bugid: either the identifier of the bug to retrieve or directly
        the bug object
    :returns: the list of the people (their email address) that commented
        on the specified ticket

    '''

    try:
        bugbz = get_bug(int(bugid))
    except ValueError:
        bugbz = bugid
    users = set([com['author'] for com in bugbz.comments])
    users.add(bugbz.creator)

    return users


def __get_fas_user_by_email(email_address):
    ''' For a provided email_address returned the associated FAS user.
    The email_address can be either the FAS email address or the one used
    in bugzilla.

    :arg email_address: the email address of the user to retrieve in FAS.

    '''
    if email_address in FASCLIENT._AccountSystem__alternate_email:
        userid = FASCLIENT._AccountSystem__alternate_email[email_address]

    else:
        try:
            userid = FASCLIENT.people_query(
                constraints={'email': email_address},
                columns=['id']
            )
        except AuthError:
            username, password = pkgdb2client.ask_password()
            FASCLIENT.username = username
            FASCLIENT.password = password
            userid = FASCLIENT.people_query(
                constraints={'email': email_address},
                columns=['id']
            )
        if userid:
            userid = userid[0].id

    user = None
    if userid:
        try:
            user = FASCLIENT.person_by_id(userid)
        except AuthError:
            username, password = pkgdb2client.ask_password()
            FASCLIENT.username = username
            FASCLIENT.password = password
            user = FASCLIENT.person_by_id(userid)

    return user


def is_packager(user):
    ''' For a provided user returned whether associated FAS user
    is a packager or not.
    The user can be either the username or an email.
    If the user is an email address, it can be either the FAS email address
    or the one used in bugzilla.

    :arg email_address: the email address of the user to retrieve in FAS.

    '''
    if '@' in user:
        fas_user = __get_fas_user_by_email(user.strip())
    else:
        try:
            fas_user = FASCLIENT.person_by_username(user)
        except AuthError:
            username, password = pkgdb2client.ask_password()
            FASCLIENT.username = username
            FASCLIENT.password = password
            fas_user = FASCLIENT.person_by_username(user)

    return fas_user \
        and 'packager' in fas_user['group_roles'] \
        and fas_user['group_roles']['packager']['role_status'] == 'approved'


def check_package_creation(info, bugid, pkgdbclient):
    ''' Performs a number of checks to see if a package review satisfies the
    criterias to create the package on pkgdb.

    Checks:
      - If the users on the review are packagers
      - If the person that approved the review (set fedora-review to +) is
        a packager
      - ...
    '''
    messages = []

    bug = get_bug(bugid)

    # Check if the title of the bug fits the expectations
    expected = 'Review Request: {0} - {1}'.format(
        info['pkg_name'], info['pkg_summary'])
    if bug.summary != expected:
        messages.append(
            ' ! The bug title does not fit the expected one\n'
            '   exp: "{0}" vs obs: "{1}"'.format(expected, bug.summary))

    # Check if the participants are packagers
    for user in get_users_in_bug(bugid):
        if not is_packager(user):
            messages.append(' ! User {0} is not a packager'.format(user))

    # Check who updated the fedora-review flag to +
    for flag in bug.flags:
        if flag['name'] == 'fedora-review' and flag['status'] == '+':
            if not is_packager(flag['setter']):
                messages.append(
                    ' ! User {0} is not a packager but set the '
                    'fedora-review flag to `+`'.format(flag['setter']))
        elif flag['name'] == 'fedora-review' and flag['status'] != '+':
            messages.append(
                ' ! fedora-review flag is no `+` but is still `%s`' %
                flag['status'])

    msgs2 = check_branch_creation(
        pkgdbclient,
        info['pkg_name'],
        info['pkg_collection'],
        info['pkg_poc'],
        new_pkg=True,
    )

    if not messages and msgs2[0].startswith(' + All checks cleared'):
        message2 = msgs2
        messages.append(
            ' + All checks cleared for review {0}: {1}'.format(
                bugid, info['pkg_name']))

    return messages


def check_branch_creation(pkgdbclient, pkg_name, clt_name, user,
                          new_pkg=False):
    ''' Performs a number of checks to see if a package should be allowed
    on a certain branch.

    Checks:
      - If the package exists in pkgdb
      - If the branch already exists
      - If the person asking for the branch is a packager
      - ...
    '''
    messages = []

    # check if the package already exists
    if not new_pkg:
        try:
            pkginfo = pkgdbclient.get_package(pkg_name)
        except pkgdb2client.PkgDBException:
            messages.append(
                ' ! Packages {0} not found in pkgdb'.format(pkg_name)
            )
            return messages

        # Check if package already has this branch
        branches = [
            pkg['collection']['branchname']
            for pkg in pkginfo['packages']
        ]

        if clt_name in branches:
            messages.append(
                ' ! Packages {0} already has the requested branch '
                '`{1}`'.format(pkg_name, clt_name)
            )

    # Check if user is a packager
    if not is_packager(user):
        messages.append(' ! User {0} is not a packager'.format(user))

    # EPEL checks
    if clt_name.lower().startswith(('el', 'epel')):
        rhel_data = get_rhel_cache(clt_name[-1])
        if pkg_name in rhel_data['packages']:
            messages.append(
                ' ! `%s` is present in RHEL %s with version: %s on arch: %s'
                % (
                    pkg_name, clt_name[-1],
                    rhel_data['packages'][pkg_name]['version'],
                    ', '.join(rhel_data['packages'][pkg_name]['arch'])
                )
            )
        else:
            messages.append(
                ' + `%s` is *not* present in RHEL %s' % (
                    pkg_name, clt_name[-1])
            )

    if not messages:
        messages.append(
            ' + All checks cleared for branch {0} for package {1}'.format(
                clt_name, pkg_name))

    return messages


def get_rhel_cache(rhel_ver):
    ''' Retrieves the info of packages for the RHEL version specified.
    If the file is already present on the disk it won't re-download them
    (expires every 24 hours).

    Returns the json structure containing the info.
    '''
    base_url = 'https://infrastructure.fedoraproject.org/repo/json/'\
        'pkg_el%s.json'

    url = base_url % rhel_ver
    output_filename = os.path.join(
        tempfile.gettempdir(), '%s_%s' % (
            datetime.utcnow().date().strftime('%Y%m%d'),
            os.path.basename(url))
    )

    if os.path.isfile(output_filename):
        with open(output_filename) as stream:
            data = json.load(stream)
    else:
        req = requests.get(url)
        if req.status_code != 200:
            raise pkgdb2client.PkgDBException(
                'Invalid RHEL version provided, json file not found')
        data = req.json()
        with open(output_filename, 'w') as stream:
            json.dump(data, stream)

    return data

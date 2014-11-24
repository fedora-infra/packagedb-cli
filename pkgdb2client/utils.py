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
import fedora_cert
from fedora.client import AccountSystem, AuthError

import pkgdb2client

try:
    USERNAME = fedora_cert.read_user_cert()
except fedora_cert.fedora_cert_error:
    LOG.debug('Could not read Fedora cert, asking for username')
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
                 'component': pkg_name})

    return bugbz


def get_bug(bugid):
    ''' Return the bug with the specified identifier.

    :arg bugid: the identifier of the bug to retrieve
    :returns: the list of the people (their email address) that commented
        on the specified ticket

    '''

    bug = BZCLIENT.getbug(bugid)
    if not '@' in bug.creator:
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
        userid = FASCLIENT.people_query(
            constraints={'email': email_address},
            columns=['id']
        )
        if userid:
            userid = userid[0].id

    user = None
    if userid:
        user = FASCLIENT.person_by_id(userid)
    else:
        LOG.info('No user id found in FAS for email %s', email_address)

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


def check_package_creation(info, bugid):
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

    if not messages:
        messages.append(
            ' + All checks cleared for review {0}: {1}'.format(
                bugid, info['pkg_name']))

    return messages


def check_branch_creation(pkgdbclient, pkg_name, clt_name, user):
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
            ' ! Packages {0} already has the requested branch `{1}`'.format(
                pkg_name, clt_name)
        )

    # Check if user is a packager
    if not is_packager(user):
        messages.append(' ! User {0} is not a packager'.format(user))

    # EPEL checks
    if clt_name.startswith(('el', 'epel')):
        messages.append(
            ' ! Nothing checked automatically, but requests is for an '
            'EPEL branch')

    if not messages:
        messages.append(
            ' + All checks cleared for package {0}'.format(pkg_name))

    return messages

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

import datetime

import requests
import fedora_cert
import xmlrpclib

from bugzilla import Bugzilla
from fedora.client import AccountSystem, AuthError

import pkgdb2client

try:
    USERNAME = fedora_cert.read_user_cert()
except fedora_cert.fedora_cert_error:
    pkgdb2client.LOG.debug('Could not read Fedora cert, asking for username')
    USERNAME = None

RH_BZ_API = 'https://bugzilla.redhat.com/xmlrpc.cgi'
BZCLIENT = None
FASCLIENT = AccountSystem(
    'https://admin.fedoraproject.org/accounts',
    username=USERNAME)


def _get_bz(url=RH_BZ_API, insecure=False):
    ''' Return a bugzilla object. '''
    global BZCLIENT
    if not BZCLIENT:
        BZCLIENT = Bugzilla(url=url)
    elif BZCLIENT.url != url:
        BZCLIENT.url = url

    BZCLIENT._sslverify = not insecure

    try:
        BZCLIENT.logged_in
    except xmlrpclib.Error:
        bz_login()

    return BZCLIENT


def bz_login():
    ''' Login on bugzilla. '''
    print('To keep going, we need to authenticate against bugzilla'
          ' at {0}'.format(BZCLIENT.url))

    username = raw_input("Bugzilla user: ")
    password = getpass.getpass("Bugzilla password: ")
    BZCLIENT.login(username, password)


def get_bugz(pkg_name):
    ''' Return the list of open bugs reported against a package.

    :arg pkg_name: the name of the package to look-up in bugzilla

    '''
    BZCLIENT = _get_bz()

    bugbz = BZCLIENT.query(
        {'bug_status': ['NEW', 'ASSIGNED', 'NEEDINFO'],
         'component': pkg_name}
    )

    return bugbz


def comment_on_bug(bugid, comment):
    ''' Comment on a bugzilla ticket.

    :arg bugid: the identifier of the bug in bugzilla
    :arg comment: the comment to post on that ticket

    '''
    bug = get_bug(bugid)

    bug.addcomment(comment)

    return bug


def get_bug_id_from_url(url):
    ''' Return the bug identifier for a given URL.

    :arg url: the url of the ticket

    '''

    bugid = url.rsplit('/', 1)[1]

    if 'id=' in url:
        bugid = url.split('id=', 1)[1]

    return bugid


def get_bug(bugid):
    ''' Return the bug with the specified identifier.

    :arg bugid: the identifier of the bug to retrieve
    :returns: the list of the people (their email address) that commented
        on the specified ticket

    '''
    BZCLIENT = _get_bz()

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


def get_fasinfo(email):
    ''' Get fas username and build a name string for the user like:
        Human Name (fas_username) <email>
        Returns (fas_username, full_info)
    '''

    fas_user = __get_fas_user_by_email(email)
    if fas_user is None:
        info = "email {} unknown to FAS".format(email)
        return info, info

    fas_username = fas_user["username"]
    if fas_username is None:
        fas_username = ""
    fas_username = fas_username.encode("utf-8")

    human_name = fas_user["human_name"]
    if human_name is None:
        human_name = "[Unknown]"
    human_name = human_name.encode("utf-8")

    full_info = "{0} ({1}) <{2}>".format(human_name, fas_username, email)
    return fas_username, full_info


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


def check_package_creation(info, bugid, pkgdbclient, requester):
    ''' Performs a number of checks to see if a package review satisfies the
    criterias to create the package on pkgdb.

    Checks:
      - If the users on the review are packagers
      - If the person that approved the review (set fedora-review to +) is
        a packager
      - ...
    '''
    messages = dict(good=[], bad=[])

    bug = get_bug(bugid)

    # Check if the title of the bug fits the expectations
    expected = 'Review Request: {0} - {1}'.format(
        info['pkg_name'], info['pkg_summary'].encode('utf-8'))

    # bug.summary is a unicode object
    bug_summary = bug.summary.encode('utf-8')

    if bug_summary == expected:
        messages["good"].append("Summary of bug {0} is: {1}".format(
            bugid, bug_summary))
    else:
        messages["bad"].append(
            'The bug title does not fit the expected one\n'
            '   exp: "{0}" vs obs: "{1}"'.format(expected, bug_summary))

    if bug.component != 'Package Review':
        messages["bad"].append(
            'Wrong bug component \n'
            '   exp: "Package Review" vs obs: "{0}"'.format(bug.component))

    if bug.product != 'Fedora':
        messages["bad"].append(
            'Wrong bug product \n'
            '   exp: "Fedora" vs obs: "{0}"'.format(bug.product))

    # Check if the participants are packagers
    for user in get_users_in_bug(bugid):
        if not is_packager(user):
            messages["bad"].append(
                'Non-packager {0} commented on review bug'.format(user))

    bug_creator, bug_creator_full = get_fasinfo(bug.creator)
    if bug_creator == requester:
        messages["good"].append("Review bug created by requester `{0}`".format(
            bug_creator_full))
    else:
        messages["bad"].append("Review bug created by `{0}` but request "
                               "by {1}".format(bug_creator_full, requester))

    # Check who updated the fedora-review flag to +
    fedora_review_checked = False
    for flag in bug.flags:
        if flag['name'] == 'fedora-review':
            fedora_review_checked = True
            if flag['status'] == '+':
                flag_setter_email = flag['setter']
                flag_setter, flag_setter_full = get_fasinfo(flag_setter_email)
                if is_packager(flag_setter):
                    messages["good"].append(
                        'Review approved by packager `{0}`'.format(
                            flag_setter_full))
                else:
                    messages["bad"].append(
                        'Review approved by non-packager `{0}`'.format(
                            flag_setter_full))
                if flag_setter_email == bug.creator:
                    messages["bad"].append(
                        'Review approved by the person creating '
                        'the ticket {0}'.format(flag_setter_full))
                if flag_setter_email != bug.assigned_to:
                    _, assignee_full = get_fasinfo(bug.assigned_to)
                    messages["bad"].append(
                        'Review approved by {0} but assignee is '
                        '{1}'.format(flag_setter_full, assignee_full))
                update_dt = flag.get('modification_date')
                if update_dt:
                    dt = datetime.datetime.strptime(
                        update_dt.value, '%Y%m%dT%H:%M:%S')
                    delta = datetime.datetime.utcnow().date() - dt.date()
                    if delta.days > 60:
                        messages["bad"].append(
                            'Review was approved more than 60 days ago, '
                            'on {0}.'.format(dt.strftime('%Y-%m-%d %H:%M:%S')))
            else:
                messages["bad"].append(
                    'Review not approved, flag set to: {0}'.format(
                        flag['status']))

    if not fedora_review_checked:
        messages["bad"].append('fedora-review flag has not been touched')


    msgs2 = check_branch_creation(
        pkgdbclient,
        info['pkg_name'],
        info['pkg_collection'],
        info['pkg_poc'],
        new_pkg=True,
        namespace=info.get('pkg_namespace', 'rpms'),
    )

    messages["bad"].extend(msgs2["bad"])
    messages["good"].extend(msgs2["good"])

    return messages


def check_branch_creation(pkgdbclient, pkg_name, clt_name, user,
                          new_pkg=False, namespace='rpms'):
    ''' Performs a number of checks to see if a package should be allowed
    on a certain branch.

    Checks:
      - If the package exists in pkgdb
      - If the branch already exists
      - If the person asking for the branch is a packager
      - ...
    '''

    messages = dict(good=[], bad=[])

    # check if the package already exists
    if not new_pkg:
        try:
            pkginfo = pkgdbclient.get_package(pkg_name, namespace=namespace)
        except pkgdb2client.PkgDBException:
            messages["bad"].append(
                'Package {0} not found in pkgdb'.format(pkg_name)
            )
            return messages

        # Check if package already has this branch
        branches = [
            pkg['collection']['branchname']
            for pkg in pkginfo['packages']
        ]

        if clt_name in branches:
            messages["bad"].append(
                'Packages {0} already has the requested branch '
                '`{1}`'.format(pkg_name, clt_name)
            )

    # Check if user is a packager
    if is_packager(user):
        messages["good"].append('Requester {0} is a packager'.format(user))
    else:
        messages["bad"].append('Requester {0} is not a packager'.format(user))

    # EPEL checks
    if clt_name.lower().startswith(('el', 'epel')):
        rhel_data = get_rhel_cache(clt_name[-1])
        if pkg_name in rhel_data['packages']:
            messages["bad"].append(
                '`%s` is present in RHEL %s with version: %s on arch: %s'
                % (
                    pkg_name, clt_name[-1],
                    rhel_data['packages'][pkg_name]['version'],
                    ', '.join(rhel_data['packages'][pkg_name]['arch'])
                )
            )
        else:
            messages["good"].append(
                '`%s` is *not* present in RHEL %s' % (
                    pkg_name, clt_name[-1])
            )

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
            datetime.datetime.utcnow().date().strftime('%Y%m%d'),
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

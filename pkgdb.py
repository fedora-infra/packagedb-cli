#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
# pkgdb - a commandline frontend for the Fedora package database
#
# Copyright (C) 2011 Pierre-Yves Chibon
# Author: Pierre-Yves Chibon <pingou@pingoured.fr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
# See http://www.gnu.org/copyleft/gpl.html  for the full text of the
# license.
"""

from fedora.client import PackageDB, AppError, ServerError
from bugzilla.rhbugzilla import RHBugzilla3
import argparse
import logging
import getpass
import koji
import sys
import re

version = '0.0.1'
kojiclient = koji.ClientSession('http://koji.fedoraproject.org/kojihub',
                {})
pkgdbclient = PackageDB('https://admin.fedoraproject.org/pkgdb')
#pkgdbclient = PackageDB('https://admin.stg.fedoraproject.org/pkgdb',
                        #insecure=True)
bzclient = RHBugzilla3(url='https://bugzilla.redhat.com/xmlrpc.cgi')
bold = "\033[1m"
red = "\033[0;31m"
reset = "\033[0;0m"

# Initial simple logging stuff
logging.basicConfig()
log = logging.getLogger("pkgdb")
if '--debug' in sys.argv:
    log.setLevel(logging.DEBUG)
elif '--verbose' in sys.argv:
    log.setLevel(logging.INFO)

cmdlist = ['acl', 'list', 'orphan', 'request']
actionlist = ['watchbugzilla', 'watchcommits', 'commit', 'approveacls']


class ActionError(Exception):
    """ This class is raised when an ACL action is requested but not in
    the list of allowed action. """
    pass


def _get_client_authentified(username=None, password=None):
    """ Returned a BaseClient with authentification

    :arg pkgdbclient a PackageDB object to which username and password
    are added
    :karg username FAS username, if None it is asked to the user
    :karg password FAS password, if None it is asked to the user
    """
    if pkgdbclient.password is None:
        if username is None:
            username = raw_input('FAS username: ')
        if password is None:
            password = getpass.getpass()
        pkgdbclient.username = username
        pkgdbclient.password = password


def _get_group_info(group, statusmap, tmpstring="", prevstring="",
                    pending=False):
    """
    For a given group (or user) check the ACL to print the ACL of the
    group or person.

    Group is the row of the pkgdb page for a given package.
    statusmap is the dictionnary which can convert the code to a human
    readable description (allows to recognize from approved, awaiting
    review or obsolete).
    The tmpstring and prevstring argument are used to fix the layout of
    the output.
    The prevstring is the previous string outputed on the row.
    The tmpstring is the row itself which is returned at the end.

    :arg group
    :arg statusmap a dict/hash mapping statuscode to human readable
    description
    :karg tmpstring temporary string used to keep information and set
    the layout. At the end it contains the whole row which is the object
    returned
    :karg prevstring previous string.
    :karg pending by default all statuscode are returned, if pending is
    true then only statuscode corresponding to "awaiting review" are
    returned
    """
    for acl in ['watchbugzilla', 'watchcommits', 'commit',
                'approveacls']:
        tmpstring = tmpstring + " " * (24 - len(tmpstring))
        if acl in group['aclOrder'].keys() and \
                group['aclOrder'][acl] is not None:
            aclout = statusmap[str(
                        group['aclOrder'][acl]['statuscode'])]
            tmpstring = tmpstring + aclout + " " * (16 - len(aclout))
            prevstring = group['aclOrder'][acl]['acl']
        else:
            tmpstring = tmpstring + " " * 16
            prevstring = ""
    if pending and "awaiting" in tmpstring.lower():
        return tmpstring.rstrip()
    elif pending:
        return
    else:
        return tmpstring.rstrip()


def _get_package_id(packagename, branch):
    """
    Retrieve the package information and return the id of the package.

    This method is used for ACL toggling (methods toggle_acl_request
    from dispatcher on packagedb).

    :arg name, name of the package to query
    :arg branch branch for which the package id is returned Branch
    can be "devel", "f-14"...
    :return package_id a string of the package_id in the packageListings
    """
    log.debug("Retrieve package_id from pkgdb for {0}".format(packagename))
    pkgdbinfo = pkgdbclient.send_request('/acls/name/{0}'.format(
            packagename, auth=False))
    if 'packageListings' in pkgdbinfo.keys():
        for branches in pkgdbinfo['packageListings']:
            if branches['collection']['branchname'] == branch:
                log.debug("Package {0} has package id: {1}".format(
                        packagename, pkgdbinfo['packageListings'][0]['id']))
                return branches['id']
    else:
        return None


def _get_active_branches():
    """
    Query pkgdb to retrieve all none-EOL branches.

    Returns a list containing the names of these branches
    """
    data = pkgdbclient.send_request('/collections/', auth=False,
            req_params={'eol': None})
    branches = dict((b[0]['branchname'], b[0])
            for b in data.collections)
    return branches.keys()


def _get_last_build(packagename, tag):
    """
    Print information about the last build of a package for a given koji
    tag.

    :arg packagename the name of the package for which we are looking for
    the last build.
    :arg tag the tag used in koji. See `koji list-tags` for the complete
    list of available tag.
    """
    log.debug("Search last build for {0} in {1}".format(packagename, tag))
    data = kojiclient.getLatestBuilds(tag,
        package=packagename)
    versions = []
    for build in data:
        nvr = "{0}-{1}-{2}".format(
            build['package_name'],
            build['version'],
            build['release'])
        versions.append(nvr)
        print "{0}Last build:{1}{2} by {3} for {4} in {5}".rstrip().format(
            " " * 8,
            " " * 5,
            build['completion_time'].split(" ")[0],
            build['owner_name'],
            version,
            tag)


def _orphan_one_package(packagename, branch='devel', username=None,
            password=None):
    """
    Orphan one package from pkgdb.
    """
    if branch is None:
        branch = 'devel'
    _get_client_authentified(username=username, password=password)

    log.info("Orphaning package {0} on branch {1}".format(packagename, branch))
    pkgdbinfo = pkgdbclient.send_request(
            '/acls/dispatcher/set_owner',
            auth=True, req_params={'owner': 'orphan',
                                    'pkg_name': packagename,
                                    'collectn_list': branch})
    log.debug("output: {0}".format(pkgdbinfo))

    if "message" in pkgdbinfo.keys():
        print "{0}{1}{2}\n".format(bold, pkgdbinfo["message"], reset)
    else:
        print "{0}Changed owner of {1} to orphan{2}\n".format(bold,
                                                              packagename,
                                                              reset)


def _retire_one_package(packagename, branch='devel', username=None,
            password=None):
    """
    Retire one package from pkgdb.
    """

    if branch is None:
        branch = 'devel'

    log.info("Retiring package {0} on branch {2}".format(packagename,
                                                            branch))

    _get_client_authentified(username=username, password=password)
    packageid = _get_package_id(packagename, branch)

    if packageid is None:
        print "Cannot retire package {0} on branch {1}, "\
                "package ID could not be found".format(packagename,
                                                        branch)
        return

    pkgdbinfo = pkgdbclient.send_request(
            '/acls/dispatcher/toggle_retirement',
            auth=True, req_params={'pkg_listing_id': packageid})

    log.debug("output: {0}".format(pkgdbinfo))

    if "retirement" in pkgdbinfo.keys():
        print "{0}{1}{2}{3}\n".format(bold, packagename,
                                      pkgdbinfo["retirement"], reset)


def get_packages(motif=None):
    """
    Retrieve the list of all packages in packagedb.
    This list can be reduced using a motif (pattern) which is optional.
    Without motif, the search can be pretty long.

    Querying "pkgdb list --all back*" will return you all the packages
    from pkgdb starting with back* (case insensitive), this includes
    orphand and eol'd packages as well as active packges.

    :karg motif the motif used to search for the packages. If the motif
    does not end with a "*", one is added.
    """
    if motif is not None:
        log.info("Query packages starting with: {0}".format(motif))
        if not motif.endswith("*"):
            motif = motif.strip() + "*"
        pkgdbinfo = pkgdbclient.send_request('/acls/list/{0}'.format(motif),
                                             auth=False,
                                             req_params={
                'tg_paginate_limit': 0})
    else:
        log.info("Query all packages")
        pkgdbinfo = pkgdbclient.send_request('/acls/list/', auth=False,
                    req_params={'tg_paginate_limit': 0})
    print pkgdbinfo['title']
    for pkg in pkgdbinfo['packages']:
        print "  ", pkg['name'], " " * (30 - len(pkg['name'])), \
                pkg['summary']
    print "Total: {0} packages".format(len(pkgdbinfo['packages']))
    log.info(pkgdbinfo.keys())


def get_orphaned_packages(motif=None, eol=False):
    """
    Retrieve the list of orphans packages.

    This list can be extended with the eol'd package by setting the eol
    argument to True.
    The motif is present for later used once the online version of
    packagedb will be adjusted to allow it.

    :karg motif the motif used to search for the packages. If the motif
    does not end with a "*", one is added.
    :karg eol if true only the EOL packages are returned.
    """
    url = '/acls/orphans/'
    if eol is not None and eol:
        log.info("Add eol'd package to the output")
        url = url + 'eol/'
    if motif is not None and 0:
        # FIXME: Loop blocked since there seem to be a bug in pkgdb here
        # see: https://admin.fedoraproject.org/pkgdb/acls/orphans
        # vs https://admin.fedoraproject.org/pkgdb/acls/orphans/b*
        # the second returns the list of orphan + eol'd
        log.info("Query orphaned packages starting with: {0}".format(motif))
        if not motif.endswith("*"):
            motif = motif.strip() + "*"
        pkgdbinfo = pkgdbclient.send_request(url + motif, auth=False,
                    req_params={'tg_paginate_limit': 0})
    else:
        log.info("Query all orphaned packages")
        pkgdbinfo = pkgdbclient.send_request(url, auth=False,
                    req_params={'tg_paginate_limit': 0})
    print pkgdbinfo.keys()
    print pkgdbinfo['title']
    for pkg in pkgdbinfo['pkgs']:
        print "  ", pkg['name'], " " * (30 - len(pkg['name'])), \
                pkg['summary']
    print "Total: {0} packages".format(len(pkgdbinfo['pkgs']))
    log.info(pkgdbinfo.keys())


def get_packager_info(packager):
    """
    Retrieve the list of all the package for which the given packager
    has
    - ownership
    - approveacls
    - commit
    - watchcommits
    - watchbugzilla
    (default options)

    :arg packager name of the packager for who to retrieve info
    """
    log.info("Query pkgdb for packager: {0}".format(packager))
    pkgdbinfo = pkgdbclient.send_request('/users/packages/{0}'.format(
                packager), auth=False,
                req_params={'tg_paginate_limit': 0})

    pkgs = []
    if pkgdbinfo['eol']:
        print "User EOL'd"
    if 'pkgs' in pkgdbinfo:
        for pkg in pkgdbinfo['pkgs']:
            log.info(pkg.keys())
            pkgs.append(pkg['name'])
            print "  ", pkg['name'], " " * (30 - len(pkg['name'])), \
                pkg['summary']
                #pkgdbinfo['statusMap'][pkg['statuscode']]
        print "Total: {0} packages".format(len(pkgdbinfo['pkgs']))
    return pkgs


def get_package_info(packagename, branch=None, pending=False,
                    extra=True):
    """
    Return information about the package.
    - Number of bugs open (with the status: new, assigned, needinfo)
    and for each branch:
    - The groups which are/have been allowed to commit on this package
    - The packager which have/have had acl on this package
    - The last build tagged in koji

    These information can be reduced to only one branch by specifying
    the desired branch as argument.

    :arg packagename the *exact* name of the package for which
    information are retrieved.
    :karg branch the name of the branch for which the information are
    retrieved. If this is None then all the branches are returned
    (default).
    :karg pending if true only the ACL information having a statuscode
    "awaiting review" are returned.
    :karg extra if True (default) extra information are returned for the
    given package. Extra information includes: the number of opened
    bugs retrieved from bugzilla, the last build information retrieved
    from koji
    """
    log.debug("Query pkgdb for {0} in branch {1}".format(packagename, branch))
    pkgdbinfo = pkgdbclient.send_request('/acls/name/{0}'.format(packagename),
                                         auth=False)

    print pkgdbinfo['title']
    if 'packageListings' in pkgdbinfo:
        print pkgdbinfo['packageListings'][0]['package']['summary']
        if extra:
            # print the number of opened bugs
            log.debug("Query bugzilla")
            bugbz = bzclient.query(
                    {'bug_status': ['NEW', 'ASSIGNED', 'NEEDINFO'],
                    'component': packagename})
            print "{0} bugs open (new, assigned, needinfo)".format(len(bugbz))
        for collection in pkgdbinfo['packageListings']:
            if branch is None or branch == \
                    collection['collection']['branchname']:

                # Retrieve ACL information
                print "{0}{1}{2}{3}Owner:{4}{5}".rstrip().format(
                    red + bold,
                    collection['collection']['branchname'],
                    reset,
                    " " * (8 -
                           len(collection['collection'][
                                'branchname'])),
                    " " * 10,
                    collection['owner'])

                # print header of the table
                tmp = " " * 24
                for acl in ["watchbugzilla", "watchcommits",
                            "commit", "approveacls"]:
                    tmp = tmp + acl + " " * (16 - len(acl))
                print tmp.rstrip()

                # print group information
                print "{0}Group:".format(" " * 8)
                for group in collection['groups']:
                    tmp = " " * 8 + group['groupname']
                    prevstring = group['groupname']
                    info = _get_group_info(group, pkgdbinfo['statusMap'],
                                        tmp, prevstring,
                                        pending=pending)
                    if info is not None and info != "":
                        print info

                # print comaintainer information
                print "{0}Comaintainer(s):".format(" " * 8)
                for people in collection['people']:
                    tmp = " " * 10 + people['username']
                    prevstring = tmp
                    info = _get_group_info(people, pkgdbinfo['statusMap'],
                                        tmp, prevstring,
                                        pending=pending)
                    if info is not None and info != "":
                        print info

                if extra:
                    # print the last build
                    tag = collection['collection']['koji_name']
                    get_last_build(packagename, tag)


def get_last_build(packagename, tag):
    """
    Retrieve from koji the latest build for a given package and a given
    tag.

    The tag can be something like: dist-F-13, dist-f14.
    This function will look at dist-f14-updates and
    dist-f14-updates-testing. It will display both updates and
    updates-testing build when they exists.

    :arg packagename the *exact* name of the package for which to
    retrieve the last build information.
    :arg tag the name of the branch for which to retrieve the
    information. This name can be 'rawhide' or f-14...
    """
    log.debug("Retrieve the last for {0} in {1}".format(packagename, tag))
    # Add build information from koji
    # for updates and updates-testing
    if "f" in tag:
        tag = tag + "-updates"
        _get_last_build(packagename, tag)
        tag = tag + "-testing"
        _get_last_build(packagename, tag)
    else:
        _get_last_build(packagename, tag)


def toggle_acl(packagename, action, branch='devel', username=None,
    password=None):
    """
    Request for a user and a branch the action for a given package.

    :arg packagename is the name of the package for which you would like
    to request an ACL.
    :arg action is action which is requested for this package, actions
    allowed are: [watchbugzilla, watchcommit, commit, approveacls]
    :karg branch name of the branch for which to toggle the ACL. By
    default this branch is 'devel' but can also be 'f-14'...
    :karg username the FAS username for the user requesting the ACL.
    :karg password the FAS password for the user requesting the ACL.
    """
    if branch is None:
        branch = 'devel'

    if action not in actionlist and action != 'all':
        raise ActionError("Action '{0}' is not in the list: {1},all".format(
                action, ",".join(actionlist)))
    _get_client_authentified(username=username, password=password)
    packageid = _get_package_id(packagename, branch)

    # if action == 'all' then we toggle all the ACLs
    if action == 'all':
        log.debug("Toggle all acl for user: {0}".format(pkgdbclient.username))
        for action in actionlist:
            log.debug(
            "Toggle acl {0} for user {1} and package {2} on branch {3}".format(
                action, pkgdbclient.username, packagename, branch))
            params = {'container_id': '{0}:{1}'.format(packageid, action)}
            pkgdbinfo = pkgdbclient.send_request(
                        '/acls/dispatcher/toggle_acl_request',
                        auth=True, req_params=params)
            log.debug(pkgdbinfo)
            if 'aclStatus' in pkgdbinfo.keys():
                msg = pkgdbinfo['aclStatus']
            else:
                msg = pkgdbinfo['message']
            log.info(
            "{0}{1}{3} for {4} on package {5} branch {6}".format(
                                                    bold,
                                                    msg,
                                                    reset,
                                                    pkgdbclient.username,
                                                    packagename,
                                                    branch))
    # else we toggle only the given one
    else:
        log.debug(
            "Toggle acl {0} for user {1} and package {2} on branch {3}".format(
                action, pkgdbclient.username, packagename, branch))
        params = {'container_id': '{0}:{1}'.format(packageid, action)}
        pkgdbinfo = pkgdbclient.send_request(
                        '/acls/dispatcher/toggle_acl_request',
                        auth=True, req_params=params)
        log.debug(pkgdbinfo)
        if 'aclStatus' in pkgdbinfo.keys():
            msg = pkgdbinfo['aclStatus']
        else:
            msg = pkgdbinfo['message']
        log.info(
            "{0}{1}{2}{3} for {4} on package {5} branch {6}".format(
                                                    bold,
                                                    msg,
                                                    reset,
                                                    pkgdbclient.username,
                                                    packagename,
                                                    branch))


def orphan_package(packagename, branch='devel', allpkgs=False,
    username=None, password=None):
    """
    Orphan packages from pkgdb.
    This implies that the owner is changed to "orphan".

    :arg packagename the name of the package to orphan
    :kwarg branch the name of the branch to orphan. By default it is
    'devel' but it can also be 'all'.
    :kwarg allpkgs default to False, if True then all the packages of
    the user will be orphaned
    :kwarg username the FAS username
    :kwarg password the FAS password of the user
    """
    if branch is None:
        branch = 'devel'
    _get_client_authentified(username=username, password=password)

    pkgs = get_packager_info(pkgdbclient.username)
    # transform the packagename to make it a regex
    motif = "^" + packagename.replace("*", ".*") + "$"
    for pkg in pkgs:
        if allpkgs is True:
            log.debug("Orphan all packages")
            if branch == "all":
                log.debug("Orphan in all branches")
                branches = _get_active_branches()
                for branch in branches:
                    _orphan_one_package(pkg, branch, username, password)
            else:
                _orphan_one_package(pkg, branch, username, password)
        elif re.match(packagename, pkg):
            log.debug("motif   : {0}".format(motif))
            log.debug("package : {0}".format(pkg))
            if branch == "all":
                log.debug("Orphan in all branches")
                branches = _get_active_branches()
                for branch in branches:
                    _orphan_one_package(pkg, branch, username, password)
            else:
                _orphan_one_package(packagename, branch, username, password)
        else:
            print "Could not find {0} in the list of your packages".format(
                    packagename)


def retire_package(packagename, branch='devel', allpkgs=False,
    username=None, password=None):
    """
    Retire packages from pkgdb.

    /!\ only orphaned package can be retired.

    :arg packagename the name of the package to be retired
    :kwarg branch the name of the branch. By default it is
    'devel' but it can also be 'all'.
    :kwarg allpkgs default to False, if True then all the packages of
    the user will be
    :kwarg username the FAS username
    :kwarg password the FAS password of the user
    """
    if branch is None:
        branch = 'devel'
    _get_client_authentified(username=username, password=password)

    if allpkgs is True:
        pkgs = get_packager_info(pkgdbclient.username)
        log.debug("Retire all packages")

        for pkg in pkgs:
            if branch == "all":
                log.debug("Retire in all branches")
                branches = _get_active_branches()
                for branch in branches:
                    _orphan_one_package(pkg, branch, username, password)
            else:
                _retire_one_package(pkg, branch, username, password)
    else:
        if branch == "all":
            log.debug("Retire in all branches")
            branches = _get_active_branches()
            for branch in branches:
                _orphan_one_package(pkg, branch, username, password)
        else:
            _retire_one_package(packagename, branch, username, password)


def setup_action_parser(action):
    """
    Parse the remaining argument for action specific arguments.

    :arg action the action for which the rest of the arguments will be
    parsed. Actions can be "acl" or "list".
    """
    log.info('Action called: {0}'.format(action))
    parser = argparse.ArgumentParser(
                usage="%(prog)s {0} [options]".format(action))

    if action == 'acl':
        parser.add_argument('package', help="Name of the package to query")
        parser.add_argument('branch', default='devel', nargs="?",
                    help="Branch of the package to query")
        parser.add_argument('--pending', action="store_true", default=False,
                    help="Display only ACL awaiting review")
        parser.add_argument('--noextra', action="store_false", default=True,
                    help="Do not display extra information (number of " \
                    "bugs opened and last build)")

    elif action == 'list':
        parser.add_argument('--all', action="store_true", default=False,
                    dest='all', help="List all packages starting " \
                    "with the given pattern (without pattern this may " \
                    "take a while)")
        parser.add_argument('--orphaned', action="store_true", default=False,
                    dest='orphaned', help="List all orphaned packages")
        parser.add_argument('--eol', action="store_true", default=False,
                    dest='eol', 
                    help="List all orphaned and eol'd packages")
        parser.add_argument('--user', dest='username', default=False,
                    help="List all the packages of the user <user>")
        parser.add_argument('pattern', default=None, nargs="?",
                    help="Pattern to query")

    elif action == 'orphan':
        parser.add_argument('package',
                    help="Name of the package to orphan or " \
                    "simple pattern")
        parser.add_argument('branch', default='devel', nargs="?",
                    help="Branch of the package to orphan " \
                    "(default: devel, can be: all)")
        parser.add_argument('--retire', action="store_true", default=False,
                    help="Retire the given package")
        parser.add_argument('--all', action="store_true", default=False,
                    help="Orphan all your packages")

    elif action == "request":
        parser.add_argument('package', help="Name of the package")
        parser.add_argument("action",
                    help="Request a specific ACL for this package " \
                    "(actions are {0})".format(", ".join(actionlist)))
        parser.add_argument('branch', default='devel', nargs="?",
                    help="Branch of the package for which the ACL is " \
                    "requested (default: devel)")
    return parser


def setup_parser():
    """
    Set the main arguments.
    """
    usage = "\nCommands: {0}".format(', '.join(cmdlist))
    parser = argparse.ArgumentParser(
    usage="%(prog)s [global options] COMMAND [options]" + usage,
    prog="pkgdb")
    # General connection options
    parser.add_argument('command')
    parser.add_argument('argument', nargs=argparse.REMAINDER)
    parser.add_argument('--user', dest="username",
                help="FAS username")
    parser.add_argument('--password', dest="password",
                help="FAS password (if not provided, will be asked " \
                "later)")
    parser.add_argument('--verbose', action='store_true',
                help="give more info about what's going on")
    parser.add_argument('--debug', action='store_true',
                help="output bunches of debugging info")
    return parser


def main():
    """ Main function """
    # Set up parser for global args
    parser = setup_parser()
    # Parse the commandline
    arg = parser.parse_args()
    # Get our action from these args
    if arg.command in cmdlist:
        action = arg.command
    else:
        raise argparse.ArgumentTypeError(
            "command must be one of: {0}".format(','.join(cmdlist)))
    # Parse action-specific args
    action_parser = setup_action_parser(action)
    log.info("*** {0}".format(", ".join(arg.argument)))
    args = action_parser.parse_args(arg.argument)
    if action == "acl":
        log.info("package : {0}".format(args.package))
        log.info("branch  : {0}".format(args.branch))
        #log.info("approve : {0}".format(args.approve))
        get_package_info(args.package, args.branch, args.pending,
                        args.noextra)

    elif action == "list":
        log.info("pattern : {0}".format(args.pattern))
        log.info("all     : {0}".format(args.all))
        log.info("user    : {0}".format(args.username))
        if(args.all is not None and args.all):
            log.info(args)
            get_packages("*")
        elif (args.orphaned is not None and args.orphaned):
            get_orphaned_packages(args.pattern, args.eol)
        elif (args.username is not None and args.username):
            get_packager_info(args.username)
        elif (args.pattern is not None):
            get_packages(args.pattern)
        else:
            raise argparse.ArgumentTypeError(
            "Not enough argument given")

    elif action == "orphan":
        log.info("user    : {0}".format(arg.username))
        log.info("package : {0}".format(args.package))
        log.info("branch  : {0}".format(args.branch))
        #log.info("pattern : {0}".format(args.pattern))
        log.info("all     : {0}".format(args.all))
        log.info("retire  : {0}".format(args.retire))
        orphan_package(args.package, args.branch, args.all,
                arg.username, arg.password)
        if args.retire is True:
            retire_package(args.package, args.branch,
                arg.username, arg.password)

    elif action == "request":
        log.info("user    : {0}".format(arg.username))
        log.info("package : {0}".format(args.package))
        log.info("branch  : {0}".format(args.branch))
        log.info("acl     : {0}".format(args.action))
        toggle_acl(args.package, args.action, args.branch,
                arg.username, arg.password)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\nInterrupted by user."
        sys.exit(1)
    except argparse.ArgumentTypeError, e:
        print "\nError: {0}".format(e)
        sys.exit(2)
    except ServerError, e:
        print '{0}'.format(e)
        sys.exit(3)
    except AppError, e:
        print '{0}: {1}'.format(e.name, e.message)
        sys.exit(4)
    except Exception, e:
        print 'Error: {0}'.format(e)
        sys.exit(5)

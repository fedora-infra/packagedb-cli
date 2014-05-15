# -*- coding: utf-8 -*-

"""
# pkgdb2 - a commandline frontend for the Fedora package database v2
#
# Copyright (C) 2014 Red Hat Inc
# Copyright (C) 2013 Pierre-Yves Chibon
# Author: Pierre-Yves Chibon <pingou@pingoured.fr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
# See http://www.gnu.org/copyleft/gpl.html  for the full text of the
# license.
"""

from fedora.client import (AccountSystem, AppError, ServerError)
from bugzilla.rhbugzilla import RHBugzilla
from pkgdb2client import PkgDB, PkgDBException, __version__
import argparse
import logging
import getpass
import koji
import fedora_cert


KOJI_HUB = 'http://koji.fedoraproject.org/kojihub'
RH_BZ_API = 'https://bugzilla.redhat.com/xmlrpc.cgi'

pkgdbclient = PkgDB('https://admin.fedoraproject.org/pkgdb')
fasclient = AccountSystem('https://admin.fedoraproject.org/accounts')
BOLD = "\033[1m"
RED = "\033[0;31m"
RESET = "\033[0;0m"

# Initial simple logging stuff
logging.basicConfig()
PKGDBLOG = logging.getLogger("pkgdb2client")
LOG = logging.getLogger("pkgdb-cli")

ACTIONLIST = ['watchbugzilla', 'watchcommits', 'commit', 'approveacls']


class ActionError(Exception):
    ''' This class is raised when an ACL action is requested but not in
    the list of allowed action. '''
    pass


def __do_login(username=None, password=None):
    ''' Returned a BaseClient with authentification

    If the username is None, tries to retrieve it from fedora_cert.

    :arg pkgdbclient a PackageDB object to which username and password
    are added
    :karg username FAS username, if None it is asked to the user
    :karg password FAS password, if None it is asked to the user
    '''
    if pkgdbclient.is_logged_in:
        return
    else:
        if username is None:
            try:
                username = fedora_cert.read_user_cert()
            except:
                LOG.debug('Could not read Fedora cert, using login name')
                username = raw_input('FAS username: ')
        password = getpass.getpass('FAS password: ')
        pkgdbclient.username = username
        pkgdbclient.login(username, password)


def _get_acls_info(acls):
    ''' Re-order the ACLs as provided by the PkgDB API in a way that can be
    easily printed.
    '''
    output = {}
    for acl in acls:
        user = acl['fas_name']
        if user not in output:
            output[user] = {}
        output[user][acl['acl']] = acl['status']
    return output


def _get_active_branch(packagename=None):
    ''' Return a list of the active branch for a specific package or simply
    all the active branches if no package is specified.
    '''
    branches = []
    if packagename:
        output = pkgdbclient.get_package(packagename)
        for pkg in output['packages']:
            if pkg['collection']['status'] != 'EOL':
                branches.append(pkg['collection']['branchname'])
    else:
        output = pkgdbclient.get_collections(
            clt_status=['EOL', 'Under Development'])
        for collect in output['collections']:
            if collect['status'] == 'EOL':
                continue
            branches.append(collect['branchname'])
    return branches


def _get_user_packages(username):
    ''' Return a list of package whose point of contact is the username
    provided.

    :arg username: the FAS username of the user of interest

    '''
    pkgs = []
    output = pkgdbclient.get_packages(poc=username)
    for pkg in output['packages']:
        pkgs.append(pkg['name'])
    return pkgs


def _get_last_build(packagename, tag):
    '''
    Print information about the last build of a package for a given koji
    tag.

    :arg packagename: the name of the package for which we are looking for
        the last build.
    :arg tag: the tag used in koji. See `koji list-tags` for the complete
        list of available tag.

    '''
    LOG.debug("Search last build for {0} in {1}".format(packagename, tag))
    kojiclient = koji.ClientSession(KOJI_HUB, {})

    data = kojiclient.getLatestBuilds(
        tag, package=packagename)
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
            nvr,
            tag)


def get_last_build(packagename, tag):
    '''
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

    '''
    LOG.debug("Retrieve the last for {0} in {1}".format(packagename, tag))
    # Add build information from koji
    # for updates and updates-testing
    if tag == 'master':
        tag = 'rawhide'
    if "f" in tag:
        tag = tag + "-updates"
        try:
            _get_last_build(packagename, tag)
        except Exception, err:
            print err
        tag = tag + "-testing"
        try:
            _get_last_build(packagename, tag)
        except Exception, err:
            print err
    else:
        try:
            _get_last_build(packagename, tag)
        except Exception, err:
            print err


def setup_parser():
    '''
    Set the main arguments.
    '''
    parser = argparse.ArgumentParser(prog="pkgdb-cli")
    # General connection options
    parser.add_argument('--user', dest="username",
                        help="FAS username")
    parser.add_argument('--password', dest="password",
                        help="FAS password (if not provided, will be asked "
                        "later)")
    parser.add_argument('--nocolor', action='store_true',
                        help="Removes color from output")
    parser.add_argument('--verbose', action='store_true',
                        help="Gives more info about what's going on")
    parser.add_argument('--debug', action='store_true',
                        help="Outputs bunches of debugging info")
    parser.add_argument('--test', action='store_true',
                        help="Uses a test instance instead of the real pkgdb.")
    parser.add_argument('--version', action='version',
                        version='pkgdb-cli %s' % (__version__))

    subparsers = parser.add_subparsers(title='actions')

    ## ACL
    parser_acl = subparsers.add_parser(
        'acl',
        help='Request acl for a given package')
    parser_acl.add_argument('package', help="Name of the package to query")
    parser_acl.add_argument(
        'branch', default='master', nargs="?",
        help="Branch of the package to query (default: 'master', can be: "
        "'all')")
    parser_acl.add_argument(
        '--pending', action="store_true", default=False,
        help="Display only ACL awaiting review")
    parser_acl.add_argument(
        '--noextra', dest='extra', action="store_false", default=True,
        help="Do not display extra information (number of bugs opened and "
        "last build)")
    parser_acl.set_defaults(func=do_acl)

    ## List
    parser_list = subparsers.add_parser(
        'list',
        help='List package according to the specified criteria')
    parser_list.add_argument(
        '--all', action="store_true",
        default=False, dest='all',
        help="Query all the package in the collection. This may take a "
        "while.")
    parser_list.add_argument(
        '--nameonly', action="store_true",
        default=False, dest='name_only',
        help="Returns only the name of the package (without the description)")
    parser_list.add_argument(
        '--orphaned', action="store_true",
        default=False, dest='orphaned',
        help="List all orphaned packages")
    parser_list.add_argument(
        '--eol', action="store_true",
        default=False, dest='eol',
        help="List all orphaned and eol'd packages")
    parser_list.add_argument(
        '--user', dest='user', default=None,
        help="List all the packages of the user <user>")
    parser_list.add_argument(
        '--branch', dest='branch', default=None,
        help="Specify a branch (default:'all')")
    parser_list.add_argument(
        'pattern', default=None, nargs="?",
        help="Pattern to query")
    parser_list.set_defaults(func=do_list)

    ## Orphan
    parser_orphan = subparsers.add_parser(
        'orphan',
        help='Orphan package(s) according to the specified criteria')
    parser_orphan.add_argument(
        'package',
        help="Name of the package to orphan or simple pattern")
    parser_orphan.add_argument(
        'branch', default='master', nargs="?",
        help="Branch of the package to orphan (default: 'master', can be: "
        "'all')")
    parser_orphan.add_argument(
        '--retire', action="store_true", default=False,
        help="Retire the given package")
    parser_orphan.add_argument(
        '--all', action="store_true", default=False,
        help="Orphan all your packages")
    parser_orphan.set_defaults(func=do_orphan)

    ## Unorphan
    parser_unorphan = subparsers.add_parser(
        'unorphan',
        help='Unorphan package(s) according to the specified criteria')
    parser_unorphan.add_argument(
        'package',
        help="Name of the package to unorphan")
    parser_unorphan.add_argument(
        'branch', default='master', nargs="?",
        help="Branch of the package to unorphan "
        "(default: 'master', can be: 'all')")
    parser_unorphan.add_argument(
        '--all', action="store_true", default=False,
        help="Unorphan all your packages")
    parser_unorphan.add_argument(
        '--poc', default=None,
        help="FAS username of the new point of contact of the package "
        "This allows to give your package or an orphaned "
        "package to someone else. "
        "(default: current FAS user)")
    parser_unorphan.set_defaults(func=do_unorphan)

    ## Request
    parser_request = subparsers.add_parser(
        'request',
        help='Request ACLs on package(s) according to the specified criteria')
    parser_request.add_argument(
        '--cancel', action="store_true", default=False,
        help="Obsolete an ACL request")
    parser_request.add_argument(
        'package', help="Name of the package")
    parser_request.add_argument(
        "action",
        help="Request (or obsolete a request) for specific ACL on this"
        " package (actions are '{0}', 'all')".format(
            "', '".join(ACTIONLIST)))
    parser_request.add_argument(
        'branch', default='master', nargs="?",
        help="Branch of the package for which the ACL is "
        "requested (default: 'master', can be: 'all')")
    parser_request.set_defaults(func=do_request)

    ## Update
    parser_update = subparsers.add_parser(
        'update',
        help='Update ACLs on package(s) as desired')
    parser_update.add_argument('package', help="Name of the package")
    parser_update.add_argument(
        "action",
        help="Request a specific ACL for this package "
        "(actions are: '{0}', 'all')".format(
            "', '".join(ACTIONLIST)))
    parser_update.add_argument(
        'user',
        help="FAS username of the person who requested ACL "
        "on this package")
    parser_update.add_argument(
        'branch', default='master', nargs="?",
        help="Branch of the package for which the ACL is "
        "requested (default: 'master', can be: 'all')")
    parser_update.add_argument(
        '--approve', action="store_true", default=False,
        help="Approve the requested ACL")
    parser_update.add_argument(
        '--deny', action="store_true", default=False,
        help="Deny the requested ACL")
    parser_update.set_defaults(func=do_update)

    ## Collections
    parser_branch = subparsers.add_parser(
        'branches',
        help='List the active branches')
    parser_branch.add_argument(
        '--all', action="store_true", default=False,
        help="Return all the branches instead of just the active ones")
    parser_branch.set_defaults(func=do_branch)

    return parser


def do_acl(args):
    ''' Retrieves the ACLs of a package from pkgdb.

    '''
    LOG.info("package : {0}".format(args.package))
    LOG.info("branch  : {0}".format(args.branch))
    #LOG.info("approve : {0}".format(args.approve))
    bzclient = RHBugzilla(url=RH_BZ_API)

    if args.branch == 'all':
        args.branch = None
    output = pkgdbclient.get_package(args.package, branches=args.branch)

    print 'Fedora Package Database -- {0}'.format(args.package)
    if output['packages']:
        print output['packages'][0]['package']['summary']
        if args.extra:
            # print the number of opened bugs
            LOG.debug("Query bugzilla")
            bugbz = bzclient.query(
                {'bug_status': ['NEW', 'ASSIGNED', 'NEEDINFO'],
                 'component': args.package})
            print "{0} bugs open (new, assigned, needinfo)".format(len(bugbz))

    for pkg in output['packages']:
        if pkg['collection']['status'] == 'EOL':
            continue
        owner = pkg['point_of_contact']
        if owner == 'orphan':
            owner = RED + owner + RESET

        # Retrieve ACL information
        print "\n{0}{1}{2}{3}Point of Contact:{4}{5}".rstrip().format(
            RED + BOLD,
            pkg['collection']['branchname'],
            RESET,
            " " * (8 - len(pkg['collection']['branchname'])),
            " " * 5,
            owner)

        # print header of the table
        tmp = " " * 24
        for acl in ["watchbugzilla", "watchcommits",
                    "commit", "approveacls"]:
            tmp = tmp + acl + " " * (16 - len(acl))
        print tmp.rstrip()

        # print ACL information
        print "{0}ACLs:".format(" " * 8)
        acls = _get_acls_info(pkg['acls'])
        for user in acls:
            if user.startswith('group::'):
                tmp = " " * 3 + user
            else:
                tmp = " " * 10 + user
            tmp = tmp + " " * (24 - len(tmp))
            for acl_title in ["watchbugzilla", "watchcommits",
                              "commit", "approveacls"]:
                #print '\n', acl_title
                if acl_title in acls[user]:
                    aclout = acls[user][acl_title]
                    tmp = tmp + aclout + " " * (16 - len(aclout))
                else:
                    tmp = tmp + " " * 16
            if tmp is not None and tmp.strip() != "":
                print tmp

        # print the last build
        if args.extra:
            tag = pkg['collection']['branchname']
            get_last_build(pkg['package']['name'], tag)


def do_list(args):
    ''' Retrieve the list of packages matching a pattern from pkgdb.

    '''
    LOG.info("pattern  : {0}".format(args.pattern))
    LOG.info("all      : {0}".format(args.all))
    LOG.info("orphaned : {0}".format(args.orphaned))
    LOG.info("user     : {0}".format(args.user))
    LOG.info("name only: {0}".format(args.name_only))
    LOG.info("branch   : {0}".format(args.branch))

    pattern = args.pattern
    if not pattern or args.all:
        pattern = '*'
    elif not pattern and not args.all:
        raise argparse.ArgumentTypeError("Not enough arguments given")

    if not pattern.endswith('*'):
        pattern += '*'

    output = pkgdbclient.get_packages(
        pattern=pattern,
        branches=args.branch,
        poc=args.user,
        orphaned=args.orphaned
    )
    cnt = 0
    for pkg in sorted(output['packages'], key=lambda pkg: (pkg['name'])):
        out = "   " + pkg['name'] + ' ' * (33 - len(pkg['name'])) + \
            pkg['summary']
        if args.name_only:
            out = "   " + pkg['name']

        print out
        cnt = cnt + 1
    if not args.name_only:
        print 'Total: {0} packages'.format(cnt)


def do_orphan(args):
    ''' Orphan a package in pkgdb.

    '''
    LOG.info("user    : {0}".format(args.username))
    LOG.info("package : {0}".format(args.package))
    LOG.info("branch  : {0}".format(args.branch))
    LOG.info("all     : {0}".format(args.all))
    LOG.info("retire  : {0}".format(args.retire))

    if args.all is True:
        pkgs = _get_user_packages(args.username)
    else:
        pkgs = [args.package]
    if args.branch == 'all':
        branches = _get_active_branch()
    else:
        branches = [args.branch]

    __do_login(args.username)

    output = pkgdbclient.orphan_packages(pkgs, branches)
    for msg in output.get('messages', []):
        print msg

    if args.retire is True:
        output = pkgdbclient.retire_packages(pkgs, branches)
        for msg in output.get('messages', []):
            print msg


def do_unorphan(args):
    ''' Unorphan a package in pkgdb.

    '''
    LOG.info("user    : {0}".format(args.username))
    LOG.info("package : {0}".format(args.package))
    LOG.info("branch  : {0}".format(args.branch))
    LOG.info("poc     : {0}".format(args.poc))
    if args.all is True:
        pkgs = _get_user_packages(args.username)
    else:
        pkgs = [args.package]
    if args.branch == 'all':
        branches = _get_active_branch()
    else:
        branches = [args.branch]

    __do_login(args.username)

    username = args.poc or args.username or pkgdbclient.username
    LOG.info("new poc : {0}".format(username))

    output = pkgdbclient.unorphan_packages(pkgs, branches, username)
    for msg in output.get('messages', []):
        print msg


def do_request(args):
    ''' Request some ACLs in pkgdb.

    '''
    LOG.info("user    : {0}".format(args.username))
    LOG.info("package : {0}".format(args.package))
    LOG.info("branch  : {0}".format(args.branch))
    LOG.info("acl     : {0}".format(args.action))
    LOG.info("cancel  : {0}".format(args.cancel))
    action = args.action
    if action == 'all':
        action = ACTIONLIST
    elif action not in ACTIONLIST:
        raise ActionError(
            'Action "{0}" is not in the list: {1},all'.format(
                action, ','.join(ACTIONLIST)))

    branch = args.branch
    if branch == 'all':
        branch = _get_active_branch(args.package)

    status = 'Awaiting Review'
    if args.cancel:
        status = 'Obsolete'

    __do_login(args.username)
    LOG.info("user    : {0}".format(pkgdbclient.username))

    output = pkgdbclient.update_acl(
        args.package,
        branches=branch,
        acls=action,
        status=status,
        user=pkgdbclient.username)

    for msg in output.get('messages', []):
        print msg


def do_update(args):
    ''' Update (approve/deny) some ACLs request on pkgdb.

    '''
    LOG.info("user      : {0}".format(args.username))
    LOG.info("package   : {0}".format(args.package))
    LOG.info("acl       : {0}".format(args.action))
    LOG.info("requester : {0}".format(args.user))
    LOG.info("branch    : {0}".format(args.branch))
    LOG.info("approve   : {0}".format(args.approve))
    LOG.info("deny      : {0}".format(args.deny))

    action = args.action
    if action == 'all':
        action = ACTIONLIST
    elif action not in ACTIONLIST:
        raise ActionError(
            'Action "{0}" is not in the list: {1},all'.format(
                action, ','.join(ACTIONLIST)))

    branch = args.branch
    if branch == 'all':
        branch = _get_active_branch(args.package)

    status = "Denied"
    if args.approve:
        status = "Approved"

    __do_login(args.username)

    output = pkgdbclient.update_acl(
        args.package,
        branches=branch,
        acls=action,
        status=status,
        user=args.user)
    for msg in output.get('messages', []):
        print msg


def do_branch(args):
    ''' List all the active branches in pkgdb.

    '''
    LOG.info("all      : {0}".format(args.all))
    LOG.info("List all active branches")
    if args.all:
        branches = pkgdbclient.get_collections()
    else:
        branches = pkgdbclient.get_collections(
            clt_status=['Active', 'Under Development'])
    cnt = 0
    for pkg in branches['collections']:
        name = '{0} {1}'.format(pkg['name'], pkg['version'])
        print "   " + pkg['branchname'] + \
            ' ' * (20 - len(pkg['branchname'])) + name + \
            ' ' * (20 - len(name)) + pkg['status']
        cnt = cnt + 1
    print 'Total: {0} collections'.format(cnt)


def main():
    ''' Main function '''
    # Set up parser for global args
    parser = setup_parser()
    # Parse the commandline
    try:
        arg = parser.parse_args()
    except argparse.ArgumentTypeError, err:
        print "\nError: {0}".format(err)
        return 2

    if arg.nocolor:
        global RED, BOLD, RESET
        RED = ""
        BOLD = ""
        RESET = ""

    if arg.debug:
        LOG.setLevel(logging.DEBUG)
        PKGDBLOG.setLevel(logging.DEBUG)
    elif arg.verbose:
        LOG.setLevel(logging.INFO)

    if arg.test:
        global fasclient, pkgdbclient
        print "Testing environment"
        fasclient = AccountSystem(
            'https://admin.stg.fedoraproject.org/accounts',
            insecure=True)
        pkgdbclient = PkgDB(
            'https://admin.stg.fedoraproject.org/pkgdb',
            insecure=True)

    return_code = 0

    try:
        arg.func(arg)
    except KeyboardInterrupt:
        print "\nInterrupted by user."
        return_code = 1
    except ServerError, err:
        LOG.debug('ServerError')
        print '{0}'.format(err)
        return_code = 3
    except ActionError, err:
        LOG.debug('ActionError')
        print '{0}'.format(err.message)
        return_code = 7
    except AppError, err:
        LOG.debug('AppError')
        print '{0}: {1}'.format(err.name, err.message)
        return_code = 4
    except PkgDBException, err:
        LOG.debug('PkgDBException')
        print '{0}'.format(err)
        return_code = 8
    except ValueError, err:
        print 'Error: {0}'.format(err)
        print 'Did you log in?'
        return_code = 6
    except Exception, err:
        print 'Error: {0}'.format(err)
        logging.exception("Generic error catched:")
        return_code = 5

    return return_code


if __name__ == '__main__':
    main()

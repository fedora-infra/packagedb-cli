# -*- coding: utf-8 -*-

"""
# pkgdb2 - a commandline frontend for the Fedora package database v2
#
# Copyright (C) 2014-2015 Red Hat Inc
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

from fedora.client import (AppError, ServerError)

import argparse
import requests
import logging
import koji
import itertools

from pkgdb2client import PkgDB, PkgDBException, __version__
import pkgdb2client
import pkgdb2client.utils


KOJI_HUB = 'http://koji.fedoraproject.org/kojihub'

pkgdbclient = PkgDB('https://admin.fedoraproject.org/pkgdb',
                    login_callback=pkgdb2client.ask_password)
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


def __get_namespace(args, kw='package'):
    ''' Return the namespace of the package as specified as an argument
    unless it was specified in the package name.
    '''
    namespace = args.namespace
    try:
        if args.__getattribute__(kw) and '/' in args.__getattribute__(kw):
            namespace = args.__getattribute__(kw).split('/', 1)[0]
    except AttributeError:
        # Raised if args doesn't have the attribute `kw`. According to
        # https://hynek.me/articles/hasattr/ hasattr is in fact a bad idea
        pass
    return namespace


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


def _get_active_branch(packagename=None, namespace='rpms'):
    ''' Return a list of the active branch for a specific package or simply
    all the active branches if no package is specified.
    '''
    LOG.debug("Retrieving all the active branches")
    global pkgdbclient
    branches = []
    if packagename:
        output = pkgdbclient.get_package(packagename, namespace=namespace)
        for pkg in output['packages']:
            if pkg['collection']['status'] != 'EOL':
                branches.append(pkg['collection']['branchname'])
    else:
        output = pkgdbclient.get_collections(
            clt_status=['Active', 'Under Development'])
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
    LOG.debug("Get the packages of user {0}".format(username))
    global pkgdbclient
    pkgs = []
    if username:
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
        print("{0}Last build:{1}{2} by {3} for {4} in {5}".rstrip().format(
            " " * 8,
            " " * 5,
            build['completion_time'].split(" ")[0],
            build['owner_name'],
            nvr,
            tag)
        )


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
        except Exception as err:
            print(err)
        tag = tag + "-testing"
        try:
            _get_last_build(packagename, tag)
        except Exception as err:
            print(err)
    else:
        try:
            _get_last_build(packagename, tag)
        except Exception as err:
            print(err)


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
    parser.add_argument('--version', action='version',
                        version='pkgdb-cli %s' % (__version__))
    parser.add_argument('--insecure', action='store_true', default=False,
                        help="Tells pkgdb-cli to ignore invalid SSL "
                        "certificates")
    parser.add_argument('--pkgdburl',
                        help="Base url of the pkgdb instance to query.")
    parser.add_argument('--fasurl',
                        help="Base url of the FAS instance to query.")
    parser.add_argument('--bzurl',
                        help="Base url of the bugzilla instance to query.")

    subparsers = parser.add_subparsers(title='actions')

    # ACL
    parser_acl = subparsers.add_parser(
        'acl',
        help='Request acl for a given package')
    parser_acl.add_argument('package', help="Name of the package to query")
    parser_acl.add_argument(
        'branch', default='master', nargs="?",
        help="Branch of the package to query (default: 'master', can be: "
        "'all')")
    parser_acl.add_argument(
        '--ns', dest='namespace', default='rpms',
        help="Namespace of the package unless specified in the package name "
        "for example via `docker/foo`, otherwise defaults to `rpms`")
    parser_acl.add_argument(
        '--pending', action="store_true", default=False,
        help="Display only ACL awaiting review")
    parser_acl.add_argument(
        '--noextra', dest='extra', action="store_false", default=True,
        help="Do not display extra information (number of bugs opened and "
        "last build)")
    parser_acl.set_defaults(func=do_acl)

    # Give
    parser_give = subparsers.add_parser(
        'give',
        help='Give package(s) according to the specified criteria')
    parser_give.add_argument(
        'package',
        help="Name of the package to give (can be: 'all')")
    parser_give.add_argument(
        'branch', default='master', nargs="?",
        help="Branch of the package to give "
        "(default: 'master', can be: 'all')")
    parser_give.add_argument(
        '--ns', dest='namespace', default='rpms',
        help="Namespace of the package unless specified in the package name "
        "for example via `docker/foo`, otherwise defaults to `rpms`")
    parser_give.add_argument(
        '--poc', default=None,
        help="FAS username of the new point of contact of the package "
        "Can be skipped if --user is specified, otherwise is mandatory.")
    parser_give.add_argument(
        '--former-poc', default=None,
        help="FAS username of the former point of contact of the package "
        "This allows to specify more branches than the former_poc has while "
        "still giving away only the branch he/she actually has.")
    parser_give.set_defaults(func=do_give)

    # List
    parser_list = subparsers.add_parser(
        'list',
        help='List package according to the specified criteria')
    parser_list.add_argument(
        '--ns', dest='namespace', default='rpms',
        help="Namespace of the package unless specified in the package name "
        "for example via `docker/foo`, otherwise defaults to `rpms`")
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
        help="List all the packages of that user <user> has ACLs on (should "
        "be provided after the `list` action)")
    parser_list.add_argument(
        '--poc', action="store_true",
        default=False, dest='poc',
        help="Used in combination with `--user`, restrict the list to the "
        "packages the user is the point of contact of")
    parser_list.add_argument(
        '--branch', dest='branch', default=None,
        help="Specify a branch (default:'all')")
    parser_list.add_argument(
        'pattern', default=None, nargs="?",
        help="Pattern to query")
    parser_list.set_defaults(func=do_list)

    # Orphan
    parser_orphan = subparsers.add_parser(
        'orphan',
        help='Orphan package(s) according to the specified criteria')
    parser_orphan.add_argument(
        'package', nargs="?",
        help="Name of the package to orphan or simple pattern (can be: 'all')")
    parser_orphan.add_argument(
        'branch', default='master', nargs="?",
        help="Branch of the package to orphan (default: 'master', can be: "
        "'all')")
    parser_orphan.add_argument(
        '--ns', dest='namespace', default='rpms',
        help="Namespace of the package unless specified in the package name "
        "for example via `docker/foo`, otherwise defaults to `rpms`")
    parser_orphan.add_argument(
        '--retire', action="store_true", default=False,
        help="Retire the given package")
    parser_orphan.add_argument(
        '--poc', default=None,
        help="When orphaning someone else's package, precise here the FAS "
        "username of the person whose packages should be orphaned. "
        "(Admin only)")
    parser_orphan.set_defaults(func=do_orphan)

    # Unorphan
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
        '--ns', dest='namespace', default='rpms',
        help="Namespace of the package unless specified in the package name "
        "for example via `docker/foo`, otherwise defaults to `rpms`")
    parser_unorphan.add_argument(
        '--poc', default=None,
        help="FAS username of the new point of contact of the package "
        "Can be skipped if --user is specified, otherwise is mandatory.")
    parser_unorphan.set_defaults(func=do_unorphan)

    # Request
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
    parser_request.add_argument(
        '--ns', dest='namespace', default='rpms',
        help="Namespace of the package unless specified in the package name "
        "for example via `docker/foo`, otherwise defaults to `rpms`")
    parser_request.set_defaults(func=do_request)

    # Update
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
        "on this package (should be provided after the `update` action)")
    parser_update.add_argument(
        'branch', default='master', nargs="?",
        help="Branch of the package for which the ACL is "
        "requested (default: 'master', can be: 'all')")
    parser_update.add_argument(
        '--ns', dest='namespace', default='rpms',
        help="Namespace of the package unless specified in the package name "
        "for example via `docker/foo`, otherwise defaults to `rpms`")
    parser_update.add_argument(
        '--approve', action="store_true", default=False,
        help="Approve the requested ACL")
    parser_update.add_argument(
        '--deny', action="store_true", default=False,
        help="Deny the requested ACL")
    parser_update.add_argument(
        '--obsolete', action="store_true", default=False,
        help="Obsolete the requested ACL")
    parser_update.set_defaults(func=do_update)

    # Collections
    parser_branch = subparsers.add_parser(
        'branches',
        help='List the active branches')
    parser_branch.add_argument(
        '--all', action="store_true", default=False,
        help="Return all the branches instead of just the active ones")
    parser_branch.set_defaults(func=do_branch)

    # Pending ACLS
    parser_pending = subparsers.add_parser(
        'pending',
        help='List the pending ACLs requests')
    parser_pending.add_argument(
        'user', default=None, nargs="?",
        help='Restrict the pending ACLs requests to those requiring action '
             'from the specified user (should be provided after the `pending` '
             'action)')
    parser_pending.set_defaults(func=do_pending)

    # Monitoring
    parser_monitoring = subparsers.add_parser(
        'monitoring',
        help='Get or Set the monitoring of a package')
    parser_monitoring.add_argument(
        'package', help="Name of the package")
    parser_monitoring.add_argument(
        'monitoring', default=None, nargs="?",
        help="Monitoring status to set the package to, if not specified "
        "will show the current status, otherwise will update it. "
        "(can be: 0, 1, nobuild)")
    parser_monitoring.add_argument(
        '--ns', dest='namespace', default='rpms',
        help="Namespace of the package unless specified in the package name "
        "for example via `docker/foo`, otherwise defaults to `rpms`")
    parser_monitoring.set_defaults(func=do_monitoring)

    # Koschei Monitoring
    parser_koschei = subparsers.add_parser(
        'koschei',
        help='Get or Set the koschei monitoring of a package')
    parser_koschei.add_argument(
        'package', help="Name of the package")
    parser_koschei.add_argument(
        'koschei', default=None, nargs="?",
        help="Koschei monitoring status to set the package to, "
        "if not specified will show the current koschei monitoring status, "
        "otherwise will update it. (can be: false, 0, true, 1)")
    parser_koschei.add_argument(
        '--ns', dest='namespace', default='rpms',
        help="Namespace of the package unless specified in the package name "
        "for example via `docker/foo`, otherwise defaults to `rpms`")
    parser_koschei.set_defaults(func=do_koschei)

    return parser


def do_acl(args):
    ''' Retrieves the ACLs of a package from pkgdb.

    '''
    namespace = __get_namespace(args)
    if '/' in args.package:
        args.package = args.package.split('/', 1)[1]
    LOG.info("package    : {0}".format(args.package))
    LOG.info("branch     : {0}".format(args.branch))
    LOG.info("namespace  : {0}".format(namespace))
    # LOG.info("approve : {0}".format(args.approve))

    if args.branch == 'all':
        args.branch = None
    output = pkgdbclient.get_package(
        args.package, branches=args.branch, namespace=namespace)

    print('Fedora Package Database -- {0}/{1}'.format(
        namespace, args.package))
    if output['packages']:
        print(output['packages'][0]['package']['summary'])
        if args.extra and namespace == 'rpms':
            # print the number of opened bugs
            LOG.debug("Query bugzilla")
            bugbz = pkgdb2client.utils.get_bugz(args.package)
            print("{0} bugs open (new, assigned, needinfo)".format(len(bugbz)))

    for pkg in sorted(
            output['packages'],
            key=lambda pkg: pkg['collection']['branchname'],
            reverse=True):
        if pkg['collection']['status'] == 'EOL':
            continue
        owner = pkg['point_of_contact']
        if owner == 'orphan':
            owner = RED + owner + RESET

        # Retrieve ACL information
        print("\n{0}{1}{2}{3}Point of Contact:{4}{5}".rstrip().format(
            RED + BOLD,
            pkg['collection']['branchname'],
            RESET,
            " " * (8 - len(pkg['collection']['branchname'])),
            " " * 5,
            owner)
        )

        # print header of the table
        tmp = " " * 24
        for acl in ["watchbugzilla", "watchcommits",
                    "commit", "approveacls"]:
            tmp = tmp + acl + " " * (16 - len(acl))
        print(tmp.rstrip())

        # print ACL information
        print("{0}ACLs:".format(" " * 8))
        if 'acls' in pkg:
            acls = _get_acls_info(pkg['acls'])
            users = sorted(acls, key=lambda user: user.replace('group::', ''))
            for user in users:
                if user.startswith('group::'):
                    tmp = " " * 3 + user
                else:
                    tmp = " " * 10 + user
                tmp = tmp + " " * (24 - len(tmp))
                for acl_title in ["watchbugzilla", "watchcommits",
                                  "commit", "approveacls"]:
                    # print '\n', acl_title
                    if acl_title in acls[user]:
                        aclout = acls[user][acl_title]
                        tmp = tmp + aclout + " " * (16 - len(aclout))
                    else:
                        tmp = tmp + " " * 16
                if tmp is not None and tmp.strip() != "":
                    print(tmp)
        else:
            print('           No ACLs found')

        # print the last build
        if args.extra:
            tag = pkg['collection']['branchname']
            get_last_build(pkg['package']['name'], tag)


def do_give(args):
    ''' Give a package to someone in pkgdb.

    '''
    namespace = __get_namespace(args)
    if '/' in args.package:
        args.package = args.package.split('/', 1)[1]

    LOG.info("user       : {0}".format(args.username))
    LOG.info("namespace  : {0}".format(namespace))
    LOG.info("package    : {0}".format(args.package))
    LOG.info("branch     : {0}".format(args.branch))
    LOG.info("poc        : {0}".format(args.poc))
    LOG.info("former_poc : {0}".format(args.former_poc))

    pkgdbclient.username = args.username
    username = args.poc or args.username
    former_poc = args.former_poc
    LOG.info("new poc : {0}".format(username))

    if args.package == 'all':
        pkgs = _get_user_packages(former_poc)
    else:
        if '*' in args.package:
            pkgs = pkgdbclient.get_packages(
                args.package, poc=former_poc, page='all',
                namespace=namespace)
            pkgs = [pkg['name'] for pkg in pkgs['packages']]
        else:
            pkgs = [args.package]

    if args.branch == 'all':
        branches = _get_active_branch()
    else:
        branches = [args.branch]

    output = pkgdbclient.update_package_poc(
        pkgs, branches, username, former_poc=former_poc,
        namespace=namespace)
    for msg in output.get('messages', []):
        print(msg)


def do_list(args):
    ''' Retrieve the list of packages matching a pattern from pkgdb.

    '''
    namespace = __get_namespace(args, kw='pattern')
    if args.pattern and '/' in args.pattern:
        args.pattern = args.pattern.split('/', 1)[1]

    LOG.info("pattern  : {0}".format(args.pattern))
    LOG.info("poc      : {0}".format(args.poc))
    LOG.info("orphaned : {0}".format(args.orphaned))
    LOG.info("user     : {0}".format(args.user))
    LOG.info("name only: {0}".format(args.name_only))
    LOG.info("branch   : {0}".format(args.branch))
    LOG.info("namespace: {0}".format(namespace))

    pattern = args.pattern
    if not pattern:
        pattern = '*'

    if not pattern.endswith('*'):
        pattern += '*'

    if args.user and not args.poc:
        version = pkgdbclient.get_version()
        if version >= (1, 6):
            output = pkgdbclient.get_packager_package(
                args.user, branches=args.branch)
            output['packages'] = output['point of contact']
            for pkg in output['co-maintained']:
                if pkg not in output['packages']:
                    output['packages'].append(pkg)
            for pkg in output['watch']:
                if pkg not in output['packages']:
                    output['packages'].append(pkg)
        else:
            # This is for backward compat but it's way slower
            output = pkgdbclient.get_packager_acls(
                packagername=args.user,
                page='all',
            )
            output2 = {'packages': []}
            for item in output['acls']:
                pkg = item['packagelist']['package']
                if pkg not in output2['packages']:
                    output2['packages'].append(pkg)
            output = output2
    else:
        output = pkgdbclient.get_packages(
            pattern=pattern,
            branches=args.branch,
            poc=args.user,
            orphaned=args.orphaned,
            page='all',
            namespace=namespace,
        )

    cnt = 0
    pkgs = sorted(output['packages'], key=lambda pkg: (pkg['name']))
    min_len = 31
    max_len = max([len(pkg['name']) for pkg in pkgs] + [min_len]) + 2
    for pkg in pkgs:
        out = "   " + pkg['name'] + ' ' * (max_len - len(pkg['name'])) + \
            pkg['summary']
        if args.name_only:
            out = "   " + pkg['name']

        print(out.encode('utf-8'))
        cnt = cnt + 1
    if not args.name_only:
        print('Total: {0} packages'.format(cnt))


def do_orphan(args):
    ''' Orphan a package in pkgdb.

    '''
    namespace = __get_namespace(args)
    if '/' in args.package:
        args.package = args.package.split('/', 1)[1]

    LOG.info("user       : {0}".format(args.username))
    LOG.info("poc        : {0}".format(args.poc))
    LOG.info("namespace  : {0}".format(namespace))
    LOG.info("package    : {0}".format(args.package))
    LOG.info("branch     : {0}".format(args.branch))
    LOG.info("retire     : {0}".format(args.retire))

    former_poc = args.poc or args.username
    if args.package == 'all':
        pkgs = _get_user_packages(former_poc)
    else:
        if '*' in args.package and former_poc:
            pkgs = pkgdbclient.get_packages(
                args.package, poc=former_poc, page='all',
                namespace=namespace)
            pkgs = [pkg['name'] for pkg in pkgs['packages']]
        else:
            pkgs = [args.package]

    if args.branch == 'all':
        branches = _get_active_branch()
    else:
        branches = [args.branch]

    pkgdbclient.username = args.username

    if args.retire is True:
        for pkg_name, pkg_branch in itertools.product(
                pkgs, branches):
            dead_url = \
                'http://pkgs.fedoraproject.org/cgit/{0}.git/plain/'\
                'dead.package?h={1}'.format(pkg_name, pkg_branch)
            req = requests.get(dead_url)
            if req.status_code != 200 or not req.text.strip():
                print('No `dead.package` for %s on %s, please use '
                      '`fedpkg retire`' % (pkg_name, pkg_branch))
                return
        output = pkgdbclient.retire_packages(
            pkgs, branches, namespace=namespace)
    else:
        output = pkgdbclient.orphan_packages(
            pkgs, branches, former_poc=former_poc, namespace=namespace)

    for msg in output.get('messages', []):
        print(msg)


def do_pending(args):
    ''' List pending ACLs requests.

    '''
    LOG.info("user    : {0}".format(args.user or args.username))
    output = pkgdbclient.get_pending_acls(args.user or args.username)
    for msg in output.get('pending_acls'):
        print('%(user)s requested `%(acl)s` on %(package)s '
              '(%(collection)s)' % msg)


def do_unorphan(args):
    ''' Unorphan a package in pkgdb.

    '''
    namespace = __get_namespace(args)
    if '/' in args.package:
        args.package = args.package.split('/', 1)[1]

    LOG.info("user       : {0}".format(args.username))
    LOG.info("namespace  : {0}".format(namespace))
    LOG.info("package    : {0}".format(args.package))
    LOG.info("branch     : {0}".format(args.branch))
    LOG.info("poc        : {0}".format(args.poc))

    pkgs = [args.package]

    if args.branch == 'all':
        branches = _get_active_branch()
    else:
        branches = [args.branch]

    pkgdbclient.username = args.username

    username = args.poc or args.username or pkgdbclient.username
    if username is None:
        raise argparse.ArgumentError(
            args.poc,
            'You must specify either --user or --poc with the username of '
            'the new point of contact.')
    LOG.info("new poc : {0}".format(username))

    output = pkgdbclient.unorphan_packages(
        pkgs, branches, username, namespace=namespace)
    for msg in output.get('messages', []):
        print(msg)


def do_request(args):
    ''' Request some ACLs in pkgdb.

    '''
    namespace = __get_namespace(args)
    if '/' in args.package:
        args.package = args.package.split('/', 1)[1]

    LOG.info("user       : {0}".format(args.username))
    LOG.info("namespace  : {0}".format(namespace))
    LOG.info("package    : {0}".format(args.package))
    LOG.info("branch     : {0}".format(args.branch))
    LOG.info("acl        : {0}".format(args.action))
    LOG.info("cancel     : {0}".format(args.cancel))
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

    pkgdbclient.username = args.username
    LOG.info("user    : {0}".format(pkgdbclient.username))

    output = pkgdbclient.update_acl(
        args.package,
        branches=branch,
        acls=action,
        status=status,
        user=pkgdbclient.username,
        namespace=namespace,
    )

    for msg in output.get('messages', []):
        print(msg)


def do_update(args):
    ''' Update (approve/deny) some ACLs request on pkgdb.

    '''
    namespace = __get_namespace(args)
    if '/' in args.package:
        args.package = args.package.split('/', 1)[1]

    LOG.info("user      : {0}".format(args.username))
    LOG.info("namespace : {0}".format(namespace))
    LOG.info("package   : {0}".format(args.package))
    LOG.info("acl       : {0}".format(args.action))
    LOG.info("requester : {0}".format(args.user))
    LOG.info("branch    : {0}".format(args.branch))
    LOG.info("approve   : {0}".format(args.approve))
    LOG.info("deny      : {0}".format(args.deny))
    LOG.info("obsolete  : {0}".format(args.obsolete))

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
    elif args.obsolete:
        status = "Obsolete"

    pkgdbclient.username = args.username

    output = pkgdbclient.update_acl(
        args.package,
        branches=branch,
        acls=action,
        status=status,
        user=args.user,
        namespace=namespace,
    )
    for msg in output.get('messages', []):
        print(msg)


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
        print("   " + pkg['branchname'] +
              ' ' * (20 - len(pkg['branchname'])) + name +
              ' ' * (20 - len(name)) + pkg['status']
              )
        cnt = cnt + 1
    print('Total: {0} collections'.format(cnt))


def do_monitoring(args):
    ''' Retrieve or set the monitoring status of a package from pkgdb.

    '''
    namespace = __get_namespace(args)
    if '/' in args.package:
        args.package = args.package.split('/', 1)[1]

    LOG.info("package     : {0}".format(args.package))
    LOG.info("namespace   : {0}".format(namespace))
    LOG.info("monitoring  : {0}".format(args.monitoring))

    version = pkgdbclient.get_version()
    if version < (1, 13):
        raise PkgDBException(
            'This version of PkgDB does not support monitoring')

    if not args.monitoring:
        pkg = pkgdbclient.get_package(
            args.package, branches='master', acls=False,
            namespace=namespace,
        )['packages'][0]['package']
        print("Current monitoring status of {0} is: {1}".format(
            pkg['name'], pkg['monitor']))
    else:
        output = pkgdbclient.set_monitoring_status(
            args.package, args.monitoring, namespace=namespace)
        print(output.get(
            'messages', 'Invalid output returned, please contact an admin'))


def do_koschei(args):
    ''' Retrieve or set the koschei monitoring status of a package from
    pkgdb.

    '''
    namespace = __get_namespace(args)
    if '/' in args.package:
        args.package = args.package.split('/', 1)[1]

    LOG.info("package    : {0}".format(args.package))
    LOG.info("namespace  : {0}".format(namespace))
    LOG.info("koschei    : {0}".format(args.koschei))

    version = pkgdbclient.get_version()
    if version < (1, 16):
        raise PkgDBException(
            'This version of PkgDB does not support koschei monitoring')

    if not args.koschei:
        pkg = pkgdbclient.get_package(
            args.package, branches='master', acls=False,
            namespace=namespace,
        )['packages'][0]['package']
        print("Current koschei monitoring status of {0} is: {1}".format(
            pkg['name'], pkg['koschei_monitor']))
    else:
        output = pkgdbclient.set_koschei_status(
            args.package, args.koschei, namespace=namespace)
        print(output.get(
            'messages', 'Invalid output returned, please contact an admin'))


def main():
    ''' Main function '''
    # Set up parser for global args
    parser = setup_parser()
    # Parse the commandline
    try:
        arg = parser.parse_args()
    except argparse.ArgumentTypeError as err:
        print("\nError: {0}".format(err))
        return 2

    if arg.nocolor:
        global RED, BOLD, RESET
        RED = ""
        BOLD = ""
        RESET = ""

    logging.basicConfig()
    if arg.debug:
        LOG.setLevel(logging.DEBUG)
        PKGDBLOG.setLevel(logging.DEBUG)
    elif arg.verbose:
        LOG.setLevel(logging.INFO)

    global pkgdbclient
    if arg.pkgdburl:
        print("Querying pkgdb at: %s" % arg.pkgdburl)
        pkgdbclient = PkgDB(
            arg.pkgdburl,
            login_callback=pkgdb2client.ask_password)

    pkgdbclient.insecure = arg.insecure

    if arg.bzurl:
        if not arg.bzurl.endswith('xmlrpc.cgi'):
            arg.bzurl = '%s/xmlrpc.cgi' % arg.bzurl
        print("Querying bugzilla at: %s" % arg.pkgdburl)
        pkgdb2client.utils.BZCLIENT.url = arg.bzurl
        pkgdb2client.utils.BZCLIENT._sslverify = not arg.insecure

    if arg.fasurl:
        print("Querying FAS at: %s" % arg.pkgdburl)
        pkgdb2client.utils.FASCLIENT.base_url = arg.fasurl
        pkgdb2client.utils.FASCLIENT.insecure = arg.insecure

    return_code = 0

    if arg.password:
        pkgdbclient.password = arg.password
    if arg.username:
        pkgdbclient.username = arg.username

    try:
        arg.func(arg)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        return_code = 1
    except ServerError as err:
        LOG.debug('ServerError')
        print('{0}'.format(err))
        return_code = 3
    except ActionError as err:
        LOG.debug('ActionError')
        print('{0}'.format(err.message))
        return_code = 7
    except argparse.ArgumentError as err:
        LOG.debug('ArgparseError')
        print('{0}'.format(err.message))
        return_code = 9
    except AppError as err:
        LOG.debug('AppError')
        print('{0}: {1}'.format(err.name, err.message))
        return_code = 4
    except PkgDBException as err:
        LOG.debug('PkgDBException')
        print('{0}'.format(err))
        return_code = 8
    except ValueError as err:
        print('Error: {0}'.format(err))
        print('Did you log in?')
        return_code = 6
    except Exception as err:
        print('Error: {0}'.format(err))
        logging.exception("Generic error catched:")
        return_code = 5

    return return_code


if __name__ == '__main__':
    main()

#!/usr/bin/python
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

from fedora.client import BaseClient, AppError, ServerError
from bugzilla.rhbugzilla import RHBugzilla3
import argparse
import logging
import getpass
import koji
import sys

version = '0.0.1'
kojiclient = koji.ClientSession('http://koji.fedoraproject.org/kojihub',
                {})
pkgdbclient = BaseClient('https://admin.fedoraproject.org/pkgdb')
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

cmdlist = ['acl', 'list']


def getGroupInfo(group, statusmap, tmpstring="", prevstring="",
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


def getPackages(motif=None):
    """
    Retrieve the list of all packages in packagedb.
    This list can be reduced using a motif (pattern) which is optional.
    Without motif, the search can be pretty long.

    Querying "pkgdb list --all back*" will return you all the packages
    from pkgdb starting with back* (case insensitive), this includes
    orphand and eol'd packages as well as active packges.
    """
    if motif is not None:
        log.info("Query packages starting with: %s" % (motif))
        if not motif.endswith("*"):
            motif = motif.strip() + "*"
        pkgdbinfo = pkgdbclient.send_request('/acls/list/%s' %
                    motif, auth=False,
                    req_params={'tg_paginate_limit': 0})
    else:
        log.info("Query all packages")
        pkgdbinfo = pkgdbclient.send_request('/acls/list/', auth=False,
                    req_params={'tg_paginate_limit': 0})
    print pkgdbinfo['title']
    for pkg in pkgdbinfo['packages']:
        print "  ", pkg['name'], " " * (30 - len(pkg['name'])), \
                pkg['summary']
    print "Total: %s packages" % len(pkgdbinfo['packages'])
    log.info(pkgdbinfo.keys())


def getOrphanedPackages(motif=None, eol=False):
    """
    Retrieve the list of orphans packages.

    This list can be extended with the eol'd package by setting the eol
    argument to True.
    The motif is present for later used once the online version of
    packagedb will be adjusted to allow it.
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
        log.info("Query orphaned packages starting with: %s" % (motif))
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
    print "Total: %s packages" % len(pkgdbinfo['pkgs'])
    log.info(pkgdbinfo.keys())


def getPackagerInfo(packager):
    """
    Retrieve the list of all the package for which the given packager
    has
    - ownership
    - approveacls
    - commit
    - watchcommits
    - watchbugzilla
    (default options)
    """
    log.info("Query pkgdb for packager: %s" % (packager))
    pkgdbinfo = pkgdbclient.send_request('/users/packages/%s' %
                    packager, auth=False,
                    req_params={'tg_paginate_limit': 0})
    print pkgdbinfo['title']

    if pkgdbinfo['eol']:
        print "User EOL'd"
    if 'pkgs' in pkgdbinfo:
        for pkg in pkgdbinfo['pkgs']:
            log.info(pkg.keys())
            print "  ", pkg['name'], " " * (30 - len(pkg['name'])), \
                pkg['summary']
                #pkgdbinfo['statusMap'][pkg['statuscode']]
        print "Total: %s packages" % len(pkgdbinfo['pkgs'])
    log.info(pkgdbinfo.keys())


def getPackageInfo(packagename, branch=None, pending=False,
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
    """
    log.debug("Query pkgdb for %s in branch %s" % (packagename, branch))
    pkgdbinfo = pkgdbclient.send_request('/acls/name/%s' %
                    packagename, auth=False)

    log.debug("Query bugzilla")
    bugbz = bzclient.query(
        {'bug_status': ['NEW', 'ASSIGNED', 'NEEDINFO'],
         'component': packagename})
    print pkgdbinfo['title']
    if 'packageListings' in pkgdbinfo:
        print pkgdbinfo['packageListings'][0]['package']['summary']
        if extra:
            print "%s bugs open (new, assigned, needinfo)" % len(bugbz)
        for collection in pkgdbinfo['packageListings']:
            if branch is None or branch == \
                    collection['collection']['branchname']:

                # Retrieve ACL information
                print "%s%s%s%sOwner:%s%s".rstrip() % (
                        red + bold,
                        collection['collection']['branchname'],
                        reset,
                        " " * (8 -
                            len(collection['collection'][
                                                'branchname'])),
                        " " * 10,
                        collection['owner'],
                        )

                # print header of the table
                tmp = " " * 24
                for acl in ["watchbugzilla", "watchcommits",
                        "commit", "approveacls"]:
                    tmp = tmp + acl + " " * (16 - len(acl))
                print tmp.rstrip()

                # print group information
                print "%sGroup:" % (" " * 8)
                for group in collection['groups']:
                    tmp = " " * 8 + group['groupname']
                    prevstring = group['groupname']
                    info = getGroupInfo(group, pkgdbinfo['statusMap'],
                                        tmp, prevstring,
                                        pending=pending)
                    if info is not None and info != "":
                        print info

                # print comaintainer information
                print "%sComaintainer(s):" % (" " * 8)
                for people in collection['people']:
                    tmp = " " * 10 + people['username']
                    prevstring = tmp
                    info = getGroupInfo(people, pkgdbinfo['statusMap'],
                                        tmp, prevstring,
                                        pending=pending)
                    if info is not None and info != "":
                        print info

                if extra:
                    tag = collection['collection']['koji_name']
                    getLastBuild(packagename, tag)


def getLastBuild(packagename, tag):
    """
    Retrieve from koji the latest build for a given package and a given
    tag.

    The tag can be something like: dist-F-13, dist-f14.
    This function will look at dist-f14-updates and
    dist-f14-updates-testing. It will display both updates and
    updates-testing build when they exists.
    """
    log.debug("Retrieve the last for %s in %s" % (packagename, tag))
    # Add build information from koji
    # for updates and updates-testing
    if "f" in tag:
        tag = tag + "-updates"
    log.debug("Search last build for %s in %s" % (packagename, tag))
    data = kojiclient.getLatestBuilds(tag,
        package=packagename)
    versions = []
    for build in data:
        version = "%s-%s-%s" % (
            build['package_name'], build['version'],
            build['release'])
        versions.append(version)
        print "%sLast build:%s%s by %s for %s in Updates".rstrip() % (
            " " * 8,
            " " * 5,
            build['completion_time'].split(" ")[0],
            build['owner_name'],
            version
            )
    if "f" in tag:
        tag = tag + "-testing"
    log.debug("Search last build for %s in %s" % (packagename, tag))
    data = kojiclient.getLatestBuilds(tag,
        package=packagename)
    for build in data:
        version = "%s-%s-%s" % (
            build['package_name'], build['version'],
            build['release'])
        if version not in versions:
            versions.append(version)
            print "%sLast build:%s%s by %s for %s in " \
                    "Updates-testing" % (
                " " * 6,
                " " * 5,
                build['completion_time'].split(" ")[0],
                build['owner_name'],
                version
            )


def setup_action_parser(action):
    """
    Parse the remaining argument for action specific arguments.
    """
    log.info('Action called: %s' % action)
    p = argparse.ArgumentParser(usage="%(prog)s " + \
            "%s [options]" % action)
    if action == 'acl':
        p.add_argument('package', help="Name of the package to query")
        p.add_argument('branch', default=None, nargs="?",
                    help="Branch of the package to query")
        p.add_argument('--pending', action="store_true", default=False,
                help="Display only ACL awaiting review")
        p.add_argument('--noextra', action="store_false", default=True,
                help="Do not display extra information (number of bugs"\
                " opened and last build)")
        ## I don't want the '--' but I can't find the right way w/o it
        #p.add_argument('ask', action="store_true", default=False,
                #help="Ask for acl on this package")
    elif action == 'list':
        p.add_argument('--all', action="store_true", default=False,
                dest='all', help="List all packages starting with the" \
                " given pattern (without pattern this may take a while)"
                )
        p.add_argument('--orphaned', action="store_true", default=False,
                dest='orphaned', help="List all orphaned packages")
        p.add_argument('--eol', action="store_true", default=False,
                dest='eol', help="List all orphaned and eol'd packages")
        p.add_argument('--user', dest='user', default=False,
                help="List all the packages of the user <user>")
        p.add_argument('pattern', default=None, nargs="?",
                help="Pattern to query")
    return p


def setup_parser():
    """
    Set the main arguments.
    """
    u = "\nCommands: %s" % ', '.join(cmdlist)
    p = argparse.ArgumentParser(
    usage="%(prog)s [global options] COMMAND [options]" + u,
    prog="pkgdb")
    # General connection options
    p.add_argument('command')
    p.add_argument('argument', nargs=argparse.REMAINDER)
    p.add_argument('--user',
                help="username")
    p.add_argument('--password',
                help="password")
    p.add_argument('--verbose', action='store_true',
                help="give more info about what's going on")
    p.add_argument('--debug', action='store_true',
                help="output bunches of debugging info")
    return p


def main():
    """ Main function """
    # Set up parser for global args
    parser = setup_parser()
    # Parse the commandline
    args = parser.parse_args()
    # Get our action from these args
    if args.command in cmdlist:
        action = args.command
    else:
        raise argparse.ArgumentTypeError(
            "command must be one of: %s" % ','.join(cmdlist))
    # Parse action-specific args
    action_parser = setup_action_parser(action)
    log.info("*** " + ", ".join(args.argument))
    args = action_parser.parse_args(args.argument)
    if action == "acl":
        log.info("package: %s" % args.package)
        log.info("branch: %s" % args.branch)
        getPackageInfo(args.package, args.branch, args.pending,
                        args.noextra)
    elif action == "list":
        log.info("all: %s" % args.all)
        log.info("user: %s" % args.user)
        if(args.all is not None and args.all):
            log.info(args)
            getPackages(args.pattern)
        elif (args.orphaned is not None and args.orphaned):
            getOrphanedPackages(args.pattern, args.eol)
        elif (args.user is not None and args.user):
            getPackagerInfo(args.user)
        else:
            raise argparse.ArgumentTypeError(
            "Not enough argument given")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\nInterrupted by user."
        sys.exit(1)
    except argparse.ArgumentTypeError, e:
        print "\nError: %s" % str(e)
        sys.exit(2)
    except ServerError, e:
        print '%s' % e
        sys.exit(3)
    except AppError, e:
        print '%s: %s' % (e.name, e.message)
        sys.exit(4)

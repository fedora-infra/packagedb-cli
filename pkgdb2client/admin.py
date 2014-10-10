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

from fedora.client import (AppError, ServerError)

import argparse
import requests
import logging
import koji

from pkgdb2client import PkgDB, PkgDBException, __version__
from cli import ActionError
import pkgdb2client
import utils


pkgdbclient = PkgDB('https://admin.fedoraproject.org/pkgdb',
                    login_callback=pkgdb2client.ask_password)
BOLD = "\033[1m"
RED = "\033[0;31m"
RESET = "\033[0;0m"

# Initial simple logging stuff
logging.basicConfig()
PKGDBLOG = logging.getLogger("pkgdb2client")
LOG = logging.getLogger("pkgdb-admin")


def setup_parser():
    '''
    Set the main arguments.
    '''
    parser = argparse.ArgumentParser(prog="pkgdb-admin")
    # General connection options
    parser.add_argument('--user', dest="username",
                        help="FAS username")
    parser.add_argument('--password', dest="password",
                        help="FAS password (if not provided, will be asked "
                        "later)")
    parser.add_argument('--verbose', action='store_true',
                        help="Gives more info about what's going on")
    parser.add_argument('--debug', action='store_true',
                        help="Outputs bunches of debugging info")
    parser.add_argument('--test', action='store_true',
                        help="Uses a test instance instead of the real pkgdb.")
    parser.add_argument('--version', action='version',
                        version='pkgdb-admin %s' % (__version__))

    subparsers = parser.add_subparsers(title='actions')

    # LIST
    parser_list = subparsers.add_parser(
        'list',
        help='List all the pending admin actions')
    parser_list.add_argument(
        'status', default='Awaiting Review', nargs='?',
        help='Status of the admin actions to list. Can be any of: '
        'All, Approved, Awaiting Review, Denied, Obsolete, Removed. '
        'Defaults to: Awaiting Review')
    parser_list.add_argument(
        '--package',
        help='Restrict the admin actions listed to a certain package. '
        '(Not supported for `request.package` actions)')
    parser_list.add_argument(
        '--packager',
        help='Restrict the admin actions listed to a certain packager')
    parser_list.set_defaults(func=do_list)

    # UPDATE
    parser_update = subparsers.add_parser(
        'update',
        help='Update the status of an admin action (just its status, '
        'nothing else)')
    parser_update.add_argument(
        'actionid',
        help='Identifier of the admin action to update.')
    parser_update.add_argument(
        'status',
        help='Status to update the admin action to. Can be any of: '
        'Approved, Awaiting Review, Denied, Obsolete, Removed.')
    parser_update.set_defaults(func=do_update)

    # PROCESS
    parser_update = subparsers.add_parser(
        'process',
        help='Process a pending admin action')
    parser_update.add_argument(
        'actionid',
        help='Identifier of the admin action to process.')
    parser_update.set_defaults(func=do_process)

    return parser


def do_list(args):
    ''' Retrieve the list of admin actions pending in pkgdb.

    '''
    LOG.info("status  : {0}".format(args.status))

    if args.status.lower() == 'all':
        args.status = None

    data = {
        'status': args.status
    }

    if args.package:
        data['package'] = args.package

    if args.packager:
        data['packager'] = args.packager

    data = pkgdbclient.handle_api_call('/admin/actions/', params=data)

    for cnt, action in enumerate(data['actions']):
        if action['action'] == 'request.package':
            print '#%(id)s (%(status)s) - %(user)s requested the new package '\
            '"%(pkg)s" on "%(clt)s"' % (
                {
                    'id': action['id'],
                    'status': action['status'],
                    'user': action['user'],
                    'pkg': action['info']['pkg_name'],
                    'clt': action['info']['pkg_collection'],
                }
            )

        elif action['action'] == 'request.branch':
            print '#%(id)s (%(status)s) - %(user)s requested a new branch '\
            '"%(clt)s" for "%(pkg)s"' % (
                {
                    'id': action['id'],
                    'status': action['status'],
                    'user': action['user'],
                    'pkg': action['package']['name'],
                    'clt': action['collection']['branchname'],
                }
            )

        elif action['action'] == 'request.unretire':
            print '#%(id)s (%(status)s) - %(user)s requested the ' \
            'unretirement of "%(pkg)s" on "%(clt)s"' % (
                {
                    'id': action['id'],
                    'status': action['status'],
                    'user': action['user'],
                    'pkg': action['package']['name'],
                    'clt': action['collection']['branchname'],
                }
            )

        else:
            print '#%(id)s (%(status)s) - %(action)s by %(user)s is not '\
            'handled by pkgdb-admin' % (
                {
                    'id': action['id'],
                    'status': action['status'],
                    'action': action['action'],
                    'user': action['user'],
                }
            )

    print 'Total: {0} actions'.format(cnt  + 1)


def do_update(args):
    ''' Update a specific admin action.

    '''
    LOG.info("user   : {0}".format(args.username))
    LOG.info("action : {0}".format(args.actionid))
    LOG.info("status : {0}".format(args.status))

    data = pkgdbclient.handle_api_call(
        '/admin/action/status',
        data={
            'id': args.actionid,
            'status': args.status
        }
    )

    for msg in data.get('messages', []):
        print msg


def _ask_what_to_do(messages):
    ''' Print the given list of information messages and ask the user
    what to do, ie: approve, deny, pass
    '''
    for message in messages:
        print message

    print 'What should we do about this requests?'
    action = raw_input('approve, deny, pass: ')
    if action.lower() not in ['approve', 'deny', 'pass']:
        print 'No valid action specified, just ignoring for now'
        action = 'pass'

    return action.lower()


def do_process(args):
    ''' Process a specific admin action.

    '''
    LOG.info("user   : {0}".format(args.username))
    LOG.info("action : {0}".format(args.actionid))

    action = pkgdbclient.handle_api_call('/admin/action/%s' % args.actionid)

    if action['status']  != 'Awaiting Review':
        print 'Action #%s is not Awaiting Review - Current status: %s' % (
            action['id'], action['status'])
        return

    if action['action'] == 'request.package':
        bugid = action['info']['pkg_review_url'].rsplit('/', 1)[1]
        if '=' in bugid:
            bugid = bugid.split('=', 1)[1]

        msgs = utils.check_package_creation(
            action['info'], bugid)

        decision = _ask_what_to_do(msgs)
        if decision == 'pass':
            data = {
                'messages': ['Action {0} un-touched'.format(args.actionid)]
            }

        elif decision == 'deny':
            data = pkgdbclient.handle_api_call(
                '/admin/action/status',
                data={
                    'id': args.actionid,
                    'status': 'Denied'
                }
            )

        else:
            data = pkgdbclient.create_package(
                pkgname=action['info']['pkg_name'],
                summary=action['info']['pkg_summary'],
                description=action['info']['pkg_description'],
                review_url=action['info']['pkg_review_url'],
                status=action['info']['pkg_status'],
                shouldopen=True,
                branches=action['info']['pkg_collection'],
                poc=action['info']['pkg_poc'],
                upstream_url=action['info']['pkg_upstream_url'],
                critpath=action['info']['pkg_critpath'],
            )

            pkgdbclient.handle_api_call(
                '/admin/action/status',
                data={
                    'id': args.actionid,
                    'status': 'Approved'
                }
            )

    elif action['action'] == 'request.branch':
        data = pkgdbclient.update_acl(
            pkgname=action['package']['name'],
            branches=action['collection']['branchname'],
            acls=['commit', 'watchbugzilla', 'watchcommits', 'approveacls'],
            status='Approved',
            user=action['user'],
        )

    else:
        print 'Action %s not supported by pkgdb-cli' % action['action']

    for msg in data.get('messages', []):
        print msg


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

    logging.basicConfig()
    if arg.debug:
        LOG.setLevel(logging.DEBUG)
        PKGDBLOG.setLevel(logging.DEBUG)
    elif arg.verbose:
        LOG.setLevel(logging.INFO)

    if arg.test:
        global pkgdbclient
        print "Testing environment"
        pkgdbclient = PkgDB(
            #'https://admin.stg.fedoraproject.org/pkgdb',
            'http://209.132.184.188/',
            login_callback=pkgdb2client.ask_password,
            insecure=True)

    return_code = 0

    if arg.password:
        pkgdbclient.password = arg.password
    if arg.username:
        pkgdbclient.username = arg.username

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

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

from fedora.client import (AppError, ServerError)

import argparse
import logging

from six.moves import input

from pkgdb2client import PkgDB, PkgDBException, __version__
from pkgdb2client.cli import ActionError
import pkgdb2client
import pkgdb2client.utils as utils


PKGDBCLIENT = PkgDB('https://admin.fedoraproject.org/pkgdb',
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
    parser.add_argument('--version', action='version',
                        version='pkgdb-admin %s' % (__version__))
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
    parser_process = subparsers.add_parser(
        'process',
        help='Process pending admin actions. All actions are procesed if none '
             'is specified.')
    parser_process.add_argument(
        'actionid', nargs='*',
        help='Identifier of the admin action to process.')
    parser_process.add_argument(
        '--package',
        help='Restrict the admin actions listed to a certain package. '
        '(Not supported for `request.package` actions)')
    parser_process.add_argument(
        '--packager',
        help='Restrict the admin actions listed to a certain packager')
    parser_process.set_defaults(func=do_process)

    # INFO
    parser_info = subparsers.add_parser(
        'info',
        help='Return a human-friendly description of the action')
    parser_info.add_argument(
        'actionid', nargs='+',
        help='Identifier of the admin action(s) of interest.')
    parser_info.set_defaults(func=do_info)

    return parser


def _action2msg(action):
    ''' Convert a given action dictionnary into a human-readable sentence.

    '''
    if action['action'] == 'request.package':
        msg = '#%(id)s (%(status)s) - %(user)s requested the new package '\
            '"%(ns)s/%(pkg)s" on "%(clt)s"\n  %(spaces)s review: '\
            '%(review_url)s' % (
                {
                    'id': action['id'],
                    'status': action['status'],
                    'user': action['user'],
                    'ns': action['info'].get('pkg_namespace', 'rpms'),
                    'pkg': action['info']['pkg_name'],
                    'clt': action['info']['pkg_collection'],
                    'spaces': ' ' * len(str(action['id'])),
                    'review_url': action['info']['pkg_review_url'],
                }
            )

    elif action['action'] == 'request.branch':
        msg = '#%(id)s (%(status)s) - %(user)s requested a new branch '\
            '"%(clt)s" for "%(ns)s/%(pkg)s"' % (
                {
                    'id': action['id'],
                    'status': action['status'],
                    'user': action['user'],
                    'ns': action['info'].get('pkg_namespace', 'rpms'),
                    'pkg': action['package']['name'],
                    'clt': action['collection']['branchname'],
                }
            )

    elif action['action'] == 'request.unretire':
        msg = '#%(id)s (%(status)s) - %(user)s requested the ' \
            'unretirement of "%(ns)s/%(pkg)s" on "%(clt)s"' % (
                {
                    'id': action['id'],
                    'status': action['status'],
                    'user': action['user'],
                    'ns': action['info'].get('pkg_namespace', 'rpms'),
                    'pkg': action['package']['name'],
                    'clt': action['collection']['branchname'],
                }
            )

    else:
        msg = '#%(id)s (%(status)s) - %(action)s by %(user)s is not '\
            'handled by pkgdb-admin' % (
                {
                    'id': action['id'],
                    'status': action['status'],
                    'action': action['action'],
                    'user': action['user'],
                }
            )

    return msg


def do_info(args):
    ''' Returns some information about a specified action.

    '''
    for actionid in args.actionid:
        LOG.info("action : {0}".format(actionid))
        action = PKGDBCLIENT.handle_api_call('/admin/action/%s' % actionid)

        print(_action2msg(action))


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

    data = PKGDBCLIENT.handle_api_call('/admin/actions/', params=data)

    ids = []
    for action in data['actions']:
        print(_action2msg(action))
        ids.append(action["id"])

    print('Total: {0} actions'.format(len(ids)))
    return ids


def do_update(args):
    ''' Update a specific admin action.

    '''
    LOG.info("user   : {0}".format(args.username))
    LOG.info("action : {0}".format(args.actionid))
    LOG.info("status : {0}".format(args.status))

    data = PKGDBCLIENT.handle_api_call(
        '/admin/action/status',
        data={
            'id': args.actionid,
            'status': args.status
        }
    )

    for msg in data.get('messages', []):
        print(msg)


def _ask_what_to_do(messages):
    ''' Print the given list of information messages and ask the user
    what to do, ie: approve, deny, pass
    '''
    for message in messages["good"]:
        print("[+] " + message)
    for message in messages["bad"]:
        print("[-] " + message)
    if not messages["bad"]:
        print("==> " + "All checks were good")

    print('\nWhat should we do about this requests?')
    action = input('approve, deny, pass: ')
    if action.lower() not in ['a', 'd', 'p', 'approve', 'deny', 'pass']:
        print('No valid action specified, just ignoring for now')
        action = 'pass'

    return action.lower()


def approve_action(actionid):
    result = PKGDBCLIENT.handle_api_call(
        '/admin/action/status',
        data={
            'id': actionid,
            'status': 'Approved'
        }
    )
    return result


def deny_action(actionid):
    message = input(
        'Could you explain why you declined this request? (this message '
        'will be sent to the user)\n=>')
    result = PKGDBCLIENT.handle_api_call(
        '/admin/action/status',
        data={
            'id': actionid,
            'status': 'Denied',
            'message': message,
        }
    )
    return result, message


def __handle_request_package(actionid, action):
    ''' Handle the new package requests. '''
    bugid = action['info']['pkg_review_url'].rsplit('/', 1)[1]
    if '=' in bugid:
        bugid = bugid.split('=', 1)[1]

    msgs = utils.check_package_creation(
        action['info'], bugid, PKGDBCLIENT, action['user'])

    bugid = utils.get_bug_id_from_url(action['info']['pkg_review_url'])

    decision = _ask_what_to_do(msgs)
    if decision in ('a', 'approve'):
        desc = action['info'].get('pkg_description', None)
        if desc:
            desc = desc.encode('utf-8')
        upstream = action['info'].get('pkg_upstream_url', None)
        if upstream:
            upstream = upstream.encode('utf-8')

        monitoring_status = action['info'].get('monitoring_status', True)
        # If we get an invalid monitoring status, use the default
        if str(monitoring_status) not in ['True', 'False', 'nobuild']:
            monitoring_status = True

        data = PKGDBCLIENT.create_package(
            pkgname=action['info']['pkg_name'].encode('utf-8'),
            summary=action['info']['pkg_summary'].encode('utf-8'),
            description=desc,
            review_url=action['info']['pkg_review_url'].encode('utf-8'),
            status=action['info']['pkg_status'].encode('utf-8'),
            shouldopen=True,
            branches=action['info']['pkg_collection'].encode('utf-8'),
            poc=action['info']['pkg_poc'].encode('utf-8'),
            upstream_url=upstream,
            critpath=action['info']['pkg_critpath'],
            namespace=action['info']['pkg_namespace'],
            monitoring_status=monitoring_status,
            koschei=action['info'].get('koschei', False),
        )

        comaintainers = action['info'].get('co-maintainers')
        if comaintainers:
            for user in comaintainers.split(','):
                PKGDBCLIENT.update_acl(
                    action['info']['pkg_name'],
                    branches=action['info']['pkg_collection'],
                    acls=['commit', 'watchbugzilla', 'watchcommits'],
                    status='Approved',
                    user=user.strip(),
                    namespace=action['info']['pkg_namespace'],
                )

        approve_action(actionid)

        url = "{0}/package/{1}/{2}".format(
            PKGDBCLIENT.base_url,
            action['info'].get('pkg_namespace', 'rpms'),
            action['info']['pkg_name'])

        utils.comment_on_bug(
            bugid,
            'Package request has been approved: %s' % url
        )

    elif decision in ('deny', 'd'):
        data, message = deny_action(actionid)

        utils.comment_on_bug(
            bugid,
            'Package request has been denied with the reason: %s' % message
        )

    else:
        data = {
            'messages': ['Action {0} un-touched'.format(actionid)]
        }

    return data


def __handle_request_branch(actionid, action, package):
    ''' Handle ne branch requests. '''
    msgs = utils.check_branch_creation(
        PKGDBCLIENT,
        action['package']['name'],
        action['collection']['branchname'],
        action['user'],
        namespace=action['package'].get('namespace', 'rpms'),
    )

    decision = None
    if package is not None:
        branch = action['info']['pkg_collection']

        # Requests for Fedora branches can be automatically approved if they
        # are from a package admin. Usually package DB approves them directly
        # only when the package was created at the same time the branches were
        # requested, it needs to be approved by a pkgdb admin.
        if branch[0] == "f":
            for acl in package["acls"]:
                if acl["fas_name"] == action["user"] and \
                        acl["acl"] == "approveacls" and \
                        acl["status"] == "Approved":
                    if len(msgs["bad"]) == 0:
                        print("Auto approving Fedora Branch request for "
                              "package admin {0}".format(action["user"]))
                        decision = "approve"

    if decision is None:
        decision = _ask_what_to_do(msgs)

    if decision in ('a', 'approve'):
        data = PKGDBCLIENT.update_acl(
            pkgname=action['package']['name'],
            branches=action['collection']['branchname'],
            acls=[
                'commit', 'watchbugzilla',
                'watchcommits', 'approveacls'
            ],
            status='Approved',
            user=action['user'],
            namespace=action['package'].get('namespace', 'rpms'),
        )

        approve_action(actionid)

    elif decision in ('deny', 'd'):
        data, _ = deny_action(actionid)
    else:
        data = {
            'messages': ['Action {0} un-touched'.format(actionid)]
        }

    return data


def __handle_request_unretire(actionid, action):
    ''' Handle unretirement requests. Do the same checks as done for new
    package requests and ask the admin to do the necessary steps by hand. '''

    bugid = action['info']['pkg_review_url'].rsplit('/', 1)[1]
    if '=' in bugid:
        bugid = bugid.split('=', 1)[1]

    # Add valuees to info that pkgdb adds to new package actions
    action['info']['pkg_name'] = action['package']['name']
    action['info']['pkg_summary'] = action['package']['summary']
    action['info']['pkg_collection'] = action['collection'][
        'branchname']
    action['info']['pkg_poc'] = action['user']
    # FIXME : Does not need to use .get() once
    # https://github.com/fedora-infra/pkgdb2/pull/333
    # is deployed.
    action['info']['pkg_namespace'] = action['package'].get(
        'namespace', 'rpms')

    msgs = utils.check_package_creation(
        action['info'], bugid, PKGDBCLIENT, action['user'])

    bugid = utils.get_bug_id_from_url(action['info']['pkg_review_url'])
    decision = _ask_what_to_do(msgs)

    if decision in ('a', 'approve'):
        cmd = ("pkgdb-cli", "unorphan", "--poc", action['info']['pkg_poc'],
               action['info']['pkg_name'], action['info']['pkg_collection'])
        input("Please run the following command (confirm with any key): " +
              " ".join(cmd))
        input("Please make sure the package is properly unblocked in koji. "
              "(Confirm with any key)")

        data = approve_action(actionid)

    elif decision in ('deny', 'd'):
        data, _ = deny_action(actionid)
    else:
        data = {
            'messages': ['Action {0} un-touched'.format(actionid)]
        }
    return data


def do_process(args):
    ''' Process a specific admin action.

    '''
    LOG.info("user   : {0}".format(args.username))

    if not args.actionid:
        args.status = "Awaiting Review"
        print('Processing all requests with status: %s' % args.status)
        ids = do_list(args)
    else:
        ids = args.actionid

    for actionid in ids:
        LOG.info("action : {0}".format(actionid))
        action = PKGDBCLIENT.handle_api_call('/admin/action/%s' % actionid)

        print(_action2msg(action))

        if action['status'] != 'Awaiting Review':
            print('Action #%s is not Awaiting Review - Current status: %s' % (
                action['id'], action['status']))
            return

        package = None
        if action['action'] == 'request.package':
            try:
                package_name = action['info']['pkg_name']
                package = PKGDBCLIENT.get_package(
                    package_name, branches=["master"],
                    namespace=action['info'].get('pkg_namespace', 'rpms'),
                )["packages"][0]
                print('Package {0} found, requalifying request.package '
                      'in request.branch'.format(action['info']['pkg_name']))
                # Adjusting the input format
                action['action'] = 'request.branch'
                action['package'] = {
                    'name': action['info']['pkg_name'],
                    'namespace': action['info'].get('pkg_namespace', 'rpms')
                }
                action['collection'] = {
                    'branchname': action['info']['pkg_collection']}

            except pkgdb2client.PkgDBException:
                pass

        if action['action'] == 'request.package':
            data = __handle_request_package(actionid, action)
        elif action['action'] == 'request.branch':
            data = __handle_request_branch(actionid, action, package)
        elif action['action'] == 'request.unretire':
            data = __handle_request_unretire(actionid, action)
        else:
            print('Action {0} not supported by pkgdb-admin'.format(
                action['action']))
            continue

        for msg in data.get('messages', []):
            print(msg)
        print('')


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

    logging.basicConfig()
    if arg.debug:
        LOG.setLevel(logging.DEBUG)
        PKGDBLOG.setLevel(logging.DEBUG)
    elif arg.verbose:
        LOG.setLevel(logging.INFO)

    global PKGDBCLIENT
    if arg.pkgdburl:
        LOG.info("Querying pkgdb at: %s", arg.pkgdburl)
        PKGDBCLIENT = PkgDB(
            arg.pkgdburl,
            login_callback=pkgdb2client.ask_password)

    PKGDBCLIENT.insecure = arg.insecure

    if arg.bzurl:
        if not arg.bzurl.endswith('xmlrpc.cgi'):
            arg.bzurl = '%s/xmlrpc.cgi' % arg.bzurl
        LOG.info("Querying bugzilla at: %s", arg.pkgdburl)
        utils._get_bz(arg.bzurl, insecure=arg.insecure)

    if arg.fasurl:
        LOG.info("Querying FAS at: %s", arg.pkgdburl)
        utils.FASCLIENT.base_url = arg.fasurl
        utils.FASCLIENT.insecure = arg.insecure

    return_code = 0

    if arg.password:
        PKGDBCLIENT.password = arg.password
    if arg.username:
        PKGDBCLIENT.username = arg.username

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

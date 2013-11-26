#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
# pkgdb2 - a python module to query the Fedora package database v2
#
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

import json

import requests


PKGDB_URL = 'http://209.132.184.188'


class PkgDBException(Exception):
    ''' Generic exception class raised when the Package DB returned an
    error.

    '''
    pass


class PkgDB(object):
    ''' PkgDB class used to interact with the Package DB instance via its
    API.

    '''

    def __init__(self, url=PKGDB_URL):
        ''' Constructor fo the PkgDB object used to query the package
        database.

        :kwarg url: the basic url to the package DB instance to query

        '''
        self.url = url

    def get_collections(self, pattern='*', status=None):
        ''' Return the list of collections matching the provided criterias.

        :kward pattern:
        :kward status:

        '''
        args = {
            'pattern': pattern,
            'status': status,
        }

        req = requests.get(
            '{0}/api/collections/'.format(self.url), params=args
        )

        output = json.loads(req.text)

        if req.status_code != 200:
            raise PkgDBException(output['error'])

        return output

    def get_package(self, pkg_name, branch=None):
        ''' Return the information of a package matching the provided
        criterias.

        :arg pkg_name:
        :kwarg branch:

        '''
        args = {
            'pkg_name': pkg_name,
            'pkg_clt': branch,
        }

        req = requests.get(
            '{0}/api/package/'.format(self.url), params=args
        )

        output = json.loads(req.text)

        if req.status_code != 200:
            raise PkgDBException(output['error'])

        return output

    def get_packages(self, pattern='*', branch=None, poc=None, orphan=None):
        ''' Return the list of packages matching the provided criterias.

        :kwarg pattern:
        :kwarg branch:
        :kwarg poc:
        :kwarg orphan:

        '''
        args = {
            'pattern': pattern,
            'branches': branch,
            'owner': poc,
            'orphan': orphan,
        }

        req = requests.get(
            '{0}/api/packages/'.format(self.url), params=args
        )

        output = json.loads(req.text)

        if req.status_code != 200:
            raise PkgDBException(output['error'])

        return output

    def orphan_packages(self, packages, branches):
        ''' Orphans the provided list of packages on the provided list of
        branches.

        :arg packages:
        :arg branches:

        '''
        if isinstance(packages, basestring):
            packages = [packages]
        if isinstance(branches, basestring):
            branches = [branches]

        args = {
            'pkg_name': ','.join(packages),
            'clt_name': ','.join(branches),
        }

        req = requests.post(
            '{0}/api/package/orphan/'.format(self.url), data=args
        )

        output = json.loads(req.text)

        if req.status_code != 200:
            raise PkgDBException(output['error'])

        return output

    def retire_packages(self, packages, branches):
        ''' Retires the provided list of packages on the provided list of
        branches.

        :arg packages:
        :arg branches:

        '''
        if isinstance(packages, basestring):
            packages = [packages]
        if isinstance(branches, basestring):
            branches = [branches]

        args = {
            'pkg_name': ','.join(packages),
            'clt_name': ','.join(branches),
        }

        req = requests.post(
            '{0}/api/package/retire/'.format(self.url), data=args
        )

        output = json.loads(req.text)

        if req.status_code != 200:
            raise PkgDBException(output['error'])

        return output

    def unorphan_packages(self, packages, branches, poc):
        ''' Un orphan the provided list of packages on the provided list of
        branches.

        :arg packages:
        :arg branches:
        :arg poc:

        '''
        if isinstance(packages, basestring):
            packages = [packages]
        if isinstance(branches, basestring):
            branches = [branches]

        args = {
            'pkg_name': ','.join(packages),
            'clt_name': ','.join(branches),
            'pkg_poc': poc,
        }

        req = requests.post(
            '{0}/api/package/unorphan/'.format(self.url), data=args
        )

        output = json.loads(req.text)

        if req.status_code != 200:
            raise PkgDBException(output['error'])

        return output

    def unretire_packages(self, packages, branches):
        ''' Un retires the provided list of packages on the provided list of
        branches.

        :arg packages:
        :arg branches:

        '''
        if isinstance(packages, basestring):
            packages = [packages]
        if isinstance(branches, basestring):
            branches = [branches]

        args = {
            'pkg_name': ','.join(packages),
            'clt_name': ','.join(branches),
        }

        req = requests.post(
            '{0}/api/package/unretire/'.format(self.url), data=args
        )

        output = json.loads(req.text)

        if req.status_code != 200:
            raise PkgDBException(output['error'])

        return output

    def update_acl(self, package, branches, acls, status, user):
        ''' Update the specified ACLs, on the specified Branches of the
        specified package

        :arg package:
        :arg branches:
        :arg acls:
        :arg status:
        :arg user:

        '''
        if isinstance(branches, basestring):
            branches = [branches]
        if isinstance(acls, basestring):
            acls = [acls]

        args = {
            'pkg_name': package,
            'pkg_branch': ','.join(branches),
            'pkg_acl': ','.join(acls),
            'acl_status': status,
            'pkg_user': user,
        }

        req = requests.post(
            '{0}/api/package/acl/'.format(self.url), data=args
        )

        output = json.loads(req.text)

        if req.status_code != 200:
            raise PkgDBException(output['error'])

        return output

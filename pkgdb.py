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
import logging

import requests

logging.basicConfig()
LOG = logging.getLogger("pkgdb")


PKGDB_URL = 'http://209.132.184.188'


class PkgDBException(Exception):
    ''' Generic exception class raised when the Package DB returned an
    error.

    '''
    pass


def _parse_service_form(response):
    """ Retrieve the attributes from the html login form.

    Basically this extracts all the field of the form so that we can
    forward them to the OpenID API.
    """
    import bs4

    parsed = bs4.BeautifulSoup(response.text)
    inputs = {}
    for child in parsed.form.find_all(name='input'):
        if child.attrs['type'] == 'submit':
            continue
        inputs[child.attrs['name']] = child.attrs['value']
    return (parsed.form.attrs['action'], inputs)


class PkgDB(object):
    ''' PkgDB class used to interact with the Package DB instance via its
    API.

    '''

    def __init__(self, url=PKGDB_URL, username=None):
        ''' Constructor fo the PkgDB object used to query the package
        database.

        :kwarg url: the basic url to the package DB instance to query
        :kwarg username: the FAS username of the user performing the
            actions

        '''
        self.url = url
        self.session = requests.session()
        self.username = username
        self.__logged = False

    @property
    def logged(self):
        ''' Return whether the user if logged in or not. '''
        return self.__logged

    def login(self, username, password, openid_insecure=False):
        ''' Login the user on pkgdb2.

        :arg username: the FAS username of the user.
        :arg password: the FAS password of the user.
        :kwarg openid_insecure: If True, do not check the openid server
            certificates against their CA's.  This means that man-in-the
            middle attacks are possible against the `BaseClient`. You might
            turn this option on for testing against a local version of a
            server with a self-signed certificate but it should be off in
            production.
        '''
        import re

        fedora_openid_api = 'https://id.fedoraproject.org/api/v1/'
        fedora_openid = '^http(s)?:\/\/(|stg.|dev.)?id\.fedoraproject\.org(/)?'
        motif = re.compile(fedora_openid)

        # Log into the service
        response = self.session.get(self.url + '/login/')

        if '<title>OpenID transaction in progress</title>' \
                in response.text:
            # requests.session should hold onto this for us....
            openid_url, data = _parse_service_form(response)
            if not motif.match(openid_url):
                raise FedoraServiceError(
                    'Un-expected openid provider asked: %s'  % openid_url)
        else:
            data = {}
            for r in response.history:
                if motif.match(r.url):
                    parsed = parse_qs(urlparse(r.url).query)
                    for key, value in parsed.items():
                        data[key] = value[0]
                    break
            else:
                raise FedoraServiceError(
                    'Unable to determine openid parameters from login: %r' %
                    openid_url)

        # Contact openid provider
        data['username'] = username
        data['password'] = password
        response = self.session.post(
            fedora_openid_api,
            data,
            verify=not openid_insecure)
        output = response.json()

        if not output['success']:
            raise PkgDBException(output['message'])

        response = self.session.post(
            output['response']['openid.return_to'],
            data=output['response'])

        self.__logged = True

        return output


    def get_collections(self, pattern='*', status=None):
        ''' Return the list of collections matching the provided criterias.

        :kward pattern:
        :kward status:

        '''
        args = {
            'pattern': pattern,
            'status': status,
        }

        req = self.session.get(
            '{0}/api/collections/'.format(self.url), params=args
        )

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
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

        req = self.session.get(
            '{0}/api/package/'.format(self.url), params=args
        )

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def get_packages(self, pattern='*', branches=None, poc=None, status=None,
            orphaned=False, acls=False, count=False):
        ''' Return the list of packages matching the provided criterias.

        :kwarg pattern:
        :kwarg branch:
        :kwarg poc:
        :kwarg orphan:

        '''
        def _get_pages(page):
            args = {
                'pattern': pattern,
                'branches': branches,
                'poc': poc,
                'status': status,
                'page': page,
            }
            if count is True:
                args['count'] = count
            if acls is True:
                args['acls'] = acls
            if orphaned is True:
                args['orphaned'] = orphaned

            req = self.session.get(
                '{0}/api/packages/'.format(self.url), params=args
            )

            output = req.json()

            if req.status_code != 200:
                LOG.debug('full output %s', output)
                raise PkgDBException(output['error'])

            return output


        output = _get_pages(1)

        page = output['page']
        total = output['pages_total']
        for i in range(2, total + 1):
            data = _get_pages(i)
            output['packages'].extend(output['packages'])

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

        req = self.session.post(
            '{0}/api/package/orphan/'.format(self.url), data=args
        )

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
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

        req = self.session.post(
            '{0}/api/package/retire/'.format(self.url), data=args
        )

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
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

        req = self.session.post(
            '{0}/api/package/unorphan/'.format(self.url), data=args
        )

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
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

        req = self.session.post(
            '{0}/api/package/unretire/'.format(self.url), data=args
        )

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
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
            'pkg_branch': branches,
            'pkg_acl': acls,
            'acl_status': status,
            'pkg_user': user,
        }

        req = self.session.post(
            '{0}/api/package/acl/'.format(self.url), data=args
        )

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

# -*- coding: utf-8 -*-

"""
# pkgdb2 - a python module to query the Fedora package database v2
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

import logging

import requests

logging.basicConfig()
LOG = logging.getLogger("pkgdb")

__version__ = '2.0'
PKGDB_URL = r'http://209.132.184.188'


class PkgDBException(Exception):
    ''' Generic exception class raised when the Package DB returned an
    error.

    '''
    pass


class PkgDBAuthException(Exception):
    ''' Authentication exception raised when trying to call a method that
    requires authentication while not being authenticated.

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

    def __init__(self, url=PKGDB_URL, username=None, insecure=False):
        ''' Constructor fo the PkgDB object used to query the package
        database.

        :kwarg url: the basic url to the package DB instance to query
        :type url: str
        :kwarg username: the FAS username of the user performing the
            actions
        :type username: str or None
        :kwarg insecure: If :data:`True` then the connection to the server
            is not checked to be sure that any SSL certificate information
            is valid.  That means that a remote host can lie about who it
            is.  Useful for development but should not be used in
            production code.
        :type insecure: bool

        '''
        self.url = url
        self.session = requests.session()
        self.username = username
        self.insecure = insecure
        self.__logged_in = False

    @property
    def is_logged_in(self):
        ''' Return whether the user if logged in or not. '''
        return self.__logged_in

    def login(self, username, password, openid_insecure=False):
        ''' Login the user on pkgdb2.

        :arg username: the FAS username of the user.
        :type username: str
        :arg password: the FAS password of the user.
        :type password: str
        :kwarg openid_insecure: If True, do not check the openid server
            certificates against their CA's.  This means that man-in-the
            middle attacks are possible against the `BaseClient`. You might
            turn this option on for testing against a local version of a
            server with a self-signed certificate but it should be off in
            production.
        :type openid_insecure: bool
        '''
        import re
        from urlparse import urlparse, parse_qs

        fedora_openid_api = r'https://id.fedoraproject.org/api/v1/'
        fedora_openid = r'^http(s)?:\/\/(|stg.|dev.)?id\.fedoraproject'\
            '\.org(/)?'
        motif = re.compile(fedora_openid)

        # Log into the service
        response = self.session.get(self.url + '/login/')

        if '<title>OpenID transaction in progress</title>' \
                in response.text:
            # requests.session should hold onto this for us....
            openid_url, data = _parse_service_form(response)
            if not motif.match(openid_url):
                raise PkgDBException(
                    'Un-expected openid provider asked: %s' % openid_url)
        else:
            data = {}
            for resp in response.history:
                if motif.match(resp.url):
                    parsed = parse_qs(urlparse(resp.url).query)
                    for key, value in parsed.items():
                        data[key] = value[0]
                    break
            else:
                raise PkgDBException(
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

        self.__logged_in = True

        return output

    ## Actual API calls

    def create_collection(self, clt_name, version, clt_status, branchname,
                          dist_tag, git_branch_name, kojiname):
        ''' Create a new collection.

        :arg clt_name: The name of the collection, for example ``Fedora``
            or ``Fedora EPEL``
        :type clt_name: str
        :arg version: The version of the collection, for example 21 or
            8
        :type version: int or str
        :arg clt_status: The status of the collection, options are: ``EOL``,
            ``Active``, ``Under Development``
        :type clt_status: str
        :arg branchname: The branch name of the collection, for example
            ``f21`` or ``epel8``
        :type branchname: str
        :arg dist_tag: The dist tag of the collection, for example
            ``fc21`` or ``.el8``
        :type dist_tag: str
        :arg git_branch_name: The branch name in git for this collection
            for example ``f21`` or ``epel7``
        :type git_branch_name: str
        :arg kojiname: The koji name for this collection, for example
            ``f21`` or ``epel7``
        :type kojiname: str
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        if not self.is_logged_in:
            raise PkgDBAuthException('Authentication required')

        args = {
            'clt_name': clt_name,
            'version': version,
            'clt_status': clt_status,
            'branchname': branchname,
            'dist_tag': dist_tag,
            'git_branch_name': git_branch_name,
            'kojiname': kojiname,
        }

        req = self.session.post(
            '{0}/api/collection/new/'.format(self.url),
            data=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def create_package(
            self, pkgname, summary, description, review_url, status,
            shouldopen, branches, poc, upstream_url, critpath=False):
        ''' Create a new package.

        :arg pkgname: The name of the package
        :type pkgname: str
        :arg summary: The summary of the package as provided in the
            spec file
        :type summary: str
        :arg description: The description of the package as provided in
            the spec file
        :type description: str
        :arg review_url: The URL to the package review where the
            package was approved
        :type review_url: str
        :arg status: The status of the package, options are:
            ``Approved``, ``Orphaned``, ``Removed``, ``Retired``
        :type status: str
        :arg shouldopen:
        :type shouldopen: bool
        :arg branches: The collection in which to add this package
        :type branches: str or list
        :arg poc: The point of contact of the package in the provided
            collection
        :type poc: str
        :arg upstream_url: The URL to the project upstream
        :type upstream_url: str
        :kwarg critpath: A boolean specifying whether to add this
            package to the critpath
        :type critpath: bool
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        if not self.is_logged_in:
            raise PkgDBAuthException('Authentication required')

        args = {
            'pkgname': pkgname,
            'summary': summary,
            'description': description,
            'review_url': review_url,
            'status': status,
            'shouldopen': shouldopen,
            'branches': branches,
            'poc': poc,
            'upstream_url': upstream_url,
        }
        if critpath:
            args['critpath'] = critpath

        req = self.session.post(
            '{0}/api/package/new/'.format(self.url),
            data=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def get_collections(self, pattern='*', clt_status=None):
        ''' Return the list of collections matching the provided criterias.

        :kward pattern: The pattern to match against the branch name of the
            collections. Defaults to ``*``
        :type pattern: str
        :kward clt_status: One or more status of the collections to retrieve,
            options are: ``EOL``, ``Active``, ``Under Development``
        :type status: str or list
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        args = {
            'pattern': pattern,
            'clt_status': clt_status,
        }

        req = self.session.get(
            '{0}/api/collections/'.format(self.url),
            params=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def get_package(self, pkgname, branch=None):
        ''' Return the information of a package matching the provided
        criterias.

        :arg pkgname: The package name to retrieve information for
        :type pkgname: str
        :kwarg branch: The branch to retrieve information for
        :type branch: str
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        args = {
            'pkgname': pkgname,
            'branch': branch,
        }

        req = self.session.get(
            '{0}/api/package/'.format(self.url),
            params=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def get_packager_acls(
            self, packagername, page=1, iterate=True, count=False):
        ''' Return the list of ACL for the packager matching the provided
        criterias.

        :arg packagername: The FAS username of the packager to retrieve the
            ACLs for
        :type packagername: str
        :kwarg page: The page number to retrieve, defaults to 1
        :type page: int
        :kwarg iterate: A boolean specifying whether to iterate over the
            multiple pages, if any, to retrieve all the results
        :type iterate: bool
        :kwarg count: A boolean to retrieve the count of ACLs the user has
            instead of the details
        :type count: bool
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        def _get_pages(page):
            ''' Retrieve a specified page of a packager's ACLs list.

            :arg page: the page number to retrieve

            '''
            args = {
                'packagername': packagername,
                'page': page,
            }
            if count is True:
                args['count'] = count

            req = self.session.get(
                '{0}/api/packager/acl/'.format(self.url),
                params=args,
                verify=not self.insecure,
            )
            LOG.debug('Called: %s with arg %s', req.url, args)

            output = req.json()

            if req.status_code != 200:
                LOG.debug('full output %s', output)
                raise PkgDBException(output['error'])

            return output

        output = _get_pages(page)

        if iterate:
            total = output['page_total']
            for i in range(2, total + 1):
                data = _get_pages(i)
                output['acls'].extend(data['acls'])

        return output

    def get_packager_stats(self, packagername):
        ''' Return for the specified user, the number of packages on each
        active branch for which he/she is the point of contact.

        :arg packagername: The FAS username of the user for which to
            retrieve the statistics
        :type username: str
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        args = {
            'packagername': packagername,
        }

        req = self.session.get(
            '{0}/api/packager/stats/'.format(self.url),
            params=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def get_packagers(self, pattern='*'):
        ''' Return the list of packagers matching the provided criterias.

        :kwarg pattern: The pattern to query the usernames of the packager
        :type pattern: str
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        args = {
            'pattern': pattern,
        }

        req = self.session.get(
            '{0}/api/packagers/'.format(self.url),
            params=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def get_packages(
            self, pattern='*', branches=None, poc=None, status=None,
            orphaned=False, acls=False, page=1, iterate=True, count=False):
        ''' Return the list of packages matching the provided criterias.

        :kwarg pattern: The pattern to match against the name of the
            packages
        :type pattern: str
        :kwarg branches: One or more branches to restrict the packages
            returned
        :type branches: str or list or None
        :kwarg poc: The point of contact of the packages to filter the
            packages returned
        :type poc: str or None
        :kwarg status: The status of the package to filter the packages
            returned, options are: ``Approved``, ``Orphaned``, ``Removed``,
            ``Retired``
        :type status: str or None
        :kwarg orphaned: A boolean to returned only orphaned packages
        :type orphaned: bool
        :kwarg acls: A boolean to return the package ACLs in the output.
            Beware, this may slow down you call considerably, maybe even
            leading to a timeout
        :type acls: bool
        :kwarg page: The page number to retrieve, defaults to 1
        :type page: int
        :kwarg iterate: A boolean specifying whether to iterate over the
            multiple pages, if any, to retrieve all the results
        :type iterate: bool
        :kwarg count: A boolean to retrieve the count of ACLs the user has
            instead of the details
        :type count: bool
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        def _get_pages(page):
            ''' Retrieve a specified page of the packages list.

            :arg page: the page number to retrieve

            '''
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
                '{0}/api/packages/'.format(self.url),
                params=args,
                verify=not self.insecure,
            )
            LOG.debug('Called: %s with arg %s', req.url, args)

            output = req.json()

            if req.status_code != 200:
                LOG.debug('full output %s', output)
                raise PkgDBException(output['error'])

            return output

        output = _get_pages(page)

        if iterate:
            total = output['page_total']
            for i in range(2, total + 1):
                data = _get_pages(i)
                output['packages'].extend(data['packages'])

        return output

    def orphan_packages(self, pkgnames, branches):
        ''' Orphans the provided list of packages on the provided list of
        branches.

        :arg pkgnames: One or more package name of the packages to orphan
        :type pkgnames: str or list
        :arg branches: One or more branch names for the collections in
            which to orphan the packages
        :type branches: str or list
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBAuthException: if this method is called while the
            client is not authenticated.
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        if not self.is_logged_in:
            raise PkgDBAuthException('Authentication required')

        args = {
            'pkgnames': pkgnames,
            'branches': branches,
        }

        req = self.session.post(
            '{0}/api/package/orphan/'.format(self.url),
            data=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def retire_packages(self, pkgnames, branches):
        ''' Retires the provided list of packages on the provided list of
        branches.

        :arg pkgnames: One or more package name of the packages to retire
        :type pkgnames: str or list
        :arg branches: One or more branch names for the collections in
            which to retire the packages
        :type branches: str or list
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBAuthException: if this method is called while the
            client is not authenticated.
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        if not self.is_logged_in:
            raise PkgDBAuthException('Authentication required')

        args = {
            'pkgnames': pkgnames,
            'branches': branches,
        }

        req = self.session.post(
            '{0}/api/package/retire/'.format(self.url),
            data=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def unorphan_packages(self, pkgnames, branches, poc):
        ''' Un orphan the provided list of packages on the provided list of
        branches.

        :arg pkgname: One or more package name of the packages to unorphan
        :type pkgname: str or list
        :arg branches: One or more branch names for the collections in
            which to unorphan the packages
        :type branches: str or list
        :arg poc:
        :type poc: str
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBAuthException: if this method is called while the
            client is not authenticated.
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        if not self.is_logged_in:
            raise PkgDBAuthException('Authentication required')

        args = {
            'pkgnames': pkgnames,
            'branches': branches,
            'poc': poc,
        }

        req = self.session.post(
            '{0}/api/package/unorphan/'.format(self.url),
            data=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def unretire_packages(self, pkgnames, branches):
        ''' Un retires the provided list of packages on the provided list of
        branches.

        :arg pkgnames: One or more package name of the packages to unretire
        :type pkgnames: str or list
        :arg branches: One or more branch names for the collections in
            which to unretire the packages
        :type branches: str or list
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBAuthException: if this method is called while the
            client is not authenticated.
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        if not self.is_logged_in:
            raise PkgDBAuthException('Authentication required')

        args = {
            'pkgnames': pkgnames,
            'branches': branches,
        }

        req = self.session.post(
            '{0}/api/package/unretire/'.format(self.url),
            data=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def update_acl(self, pkgname, branches, acls, status, user):
        ''' Update the specified ACLs, on the specified Branches of the
        specified package

        :arg pkgname: The package name of the package whom ACLs to update
        :type pkgname: str
        :arg branches: One or more branch for which to update their ACLs
        :type branches: str or list
        :arg acls: The ACL to update, options are: ``watchcommits``,
            ``watchbugzilla``, ``approveacls``, ``commit``
        :type acls: str or list
        :arg status: The status of the ACL to update, options are:
            ``Approved``, ``Awaiting Review``, ``Denied``, ``Obsolete``,
            ``Removed``
        :type status: str
        :arg user: The user for which to update the ACL (the person
            requesting new ACLs or for which to approve/deny the ACLs)
        :type user: str
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBAuthException: if this method is called while the
            client is not authenticated.
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        if not self.is_logged_in:
            raise PkgDBAuthException('Authentication required')

        args = {
            'pkgname': pkgname,
            'branches': branches,
            'acl': acls,
            'acl_status': status,
            'user': user,
        }

        req = self.session.post(
            '{0}/api/package/acl/'.format(self.url),
            data=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def update_collection_status(self, branch, clt_status):
        ''' Update the status of the specified collection.

        :arg branch: The branch name of the collection for which to
            update the status
        :type branch: str
        :arg clt_status: The new status of the collection, options are: ``EOL``,
            ``Active``, ``Under Development``
        :type clt_status: str
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBAuthException: if this method is called while the
            client is not authenticated.
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        if not self.is_logged_in:
            raise PkgDBAuthException('Authentication required')

        args = {
            'branch': branch,
            'clt_status': clt_status,
        }

        req = self.session.post(
            '{0}/api/collection/{1}/status/'.format(
                self.url, branch),
            data=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

    def update_package_poc(self, pkgnames, branches, poc):
        ''' Update the point of contact of the specified packages on the
        specified branches.

        :arg pkgnames: One or more package names of package for which to
            change the point of contact
        :type pkgnames: str or list
        :arg branches: One or more branch names for the collections for
            which to update the point of contact
        :type branches: str or list
        :arg poc:
        :type poc: str
        :return: the json object returned by the API
        :rtype: dict
        :raise PkgDBAuthException: if this method is called while the
            client is not authenticated.
        :raise PkgDBException: if the API call does not return a http code
            200.

        '''
        if not self.is_logged_in:
            raise PkgDBAuthException('Authentication required')

        args = {
            'pkgnames': pkgnames,
            'branches': branches,
            'poc': poc,
        }

        req = self.session.post(
            '{0}/api/package/acl/reassign/'.format(self.url),
            data=args,
            verify=not self.insecure,
        )
        LOG.debug('Called: %s with arg %s', req.url, args)

        output = req.json()

        if req.status_code != 200:
            LOG.debug('full output %s', output)
            raise PkgDBException(output['error'])

        return output

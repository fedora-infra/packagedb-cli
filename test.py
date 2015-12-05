#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime
import getpass
import time
import unittest
import uuid

from functools import wraps
from six.moves import input

import fedora_cert

from pkgdb2client import PkgDB, PkgDBException


PKGDB_URL = 'http://127.0.0.1:5000'
AUTH = True

if AUTH:
    try:
        USERNAME = fedora_cert.read_user_cert()
    except:
        USERNAME = input('FAS username: ')
    PASSWORD = getpass.getpass('FAS password: ')
    if not PASSWORD:
        AUTH = False

COL_NAME = str(uuid.uuid1())[:30]
PKG_NAME = str(uuid.uuid1())[:30]
VERSION = time.mktime(datetime.datetime.utcnow().timetuple())


def auth_only(function):
    """ Decorator to skip tests if AUTH is set to False """
    @wraps(function)
    def decorated_function(*args, **kwargs):
        """ Decorated function, actually does the work. """
        if AUTH:
            return function(*args, **kwargs)
        else:
            return 'Skipped'

    return decorated_function


class TestPkgdDB(unittest.TestCase):
    ''' Un-authenticated pkgdb2 tests. '''

    def setUp(self):
        """ set up data used in the tests.
        setUp is called before each test function execution.
        """
        self.pkgdb = PkgDB(PKGDB_URL, insecure=True)

    def test_get_collection(self):
        ''' Test the get_collections function. '''
        out = self.pkgdb.get_collections()
        self.assertEqual(
            sorted(out.keys()),
            ['collections', 'output'])
        self.assertTrue(len(out['collections']) >= 30)

        out = self.pkgdb.get_collections(pattern='f19')
        self.assertEqual(len(out['collections']), 1)
        self.assertEqual(out['collections'][0]['branchname'], 'f19')
        self.assertEqual(
            sorted(out.keys()),
            ['collections', 'output'])

        out = self.pkgdb.get_collections(
            clt_status=['EOL', 'Under Development'])
        self.assertEqual(
            sorted(out.keys()),
            ['collections', 'output'])
        self.assertTrue(len(out['collections']) >= 25)

    def test_get_package(self):
        ''' Test the get_package function. '''
        out = self.pkgdb.get_package('guake')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages'])
        self.assertEqual(out['output'], 'ok')
        self.assertEqual(len(out['packages']), 5)
        self.assertEqual(
            out['packages'][0]['collection']['branchname'], 'master')
        self.assertEqual(
            out['packages'][0]['package']['name'], 'guake')
        self.assertEqual(
            out['packages'][0]['point_of_contact'], 'pingou')

        out = self.pkgdb.get_package('guake', 'f20')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages'])
        self.assertEqual(out['output'], 'ok')
        self.assertEqual(len(out['packages']), 1)
        self.assertEqual(
            out['packages'][0]['collection']['branchname'], 'f20')
        self.assertEqual(
            out['packages'][0]['package']['name'], 'guake')
        out = self.pkgdb.get_package('guake', ['f20', 'f19'])
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages'])
        self.assertEqual(out['output'], 'ok')
        self.assertEqual(len(out['packages']), 2)
        self.assertEqual(
            out['packages'][0]['collection']['branchname'], 'f19')
        self.assertEqual(
            out['packages'][1]['collection']['branchname'], 'f20')
        self.assertEqual(
            out['packages'][0]['package']['name'], 'guake')
        self.assertEqual(
            out['packages'][1]['package']['name'], 'guake')

    def test_get_packager_acls(self):
        ''' Test the get_packager_acls function. '''
        out = self.pkgdb.get_packager_acls('pingou')
        self.assertEqual(
            sorted(out.keys()),
            ['acls', 'output', 'page', 'page_total'])
        self.assertEqual(len(out['acls']), 250)
        self.assertEqual(out['page_total'], 6)

        out = self.pkgdb.get_packager_acls('pingou', acls=['approveacls'])
        self.assertEqual(
            sorted(out.keys()),
            ['acls', 'output', 'page', 'page_total'])
        self.assertTrue(len(out['acls']) >= 239)
        self.assertEqual(out['page_total'], 2)

        out = self.pkgdb.get_packager_acls('pingou', page=3)
        self.assertEqual(
            sorted(out.keys()),
            ['acls', 'output', 'page', 'page_total'])
        self.assertTrue(len(out['acls']) >= 250)
        self.assertEqual(out['page_total'], 6)

        out = self.pkgdb.get_packager_acls('pingou', count=True)
        self.assertEqual(
            sorted(out.keys()),
            ['acls_count', 'output', 'page', 'page_total'])
        self.assertTrue(out['acls_count'] >= 1043)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packager_acls('pingou', poc=True, count=True)
        self.assertEqual(
            sorted(out.keys()),
            ['acls_count', 'output', 'page', 'page_total'])
        self.assertTrue(out['acls_count'] >= 750)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packager_acls('pingou', poc=False, count=True)
        self.assertEqual(
            sorted(out.keys()),
            ['acls_count', 'output', 'page', 'page_total'])
        self.assertTrue(out['acls_count'] >= 239)
        self.assertEqual(out['page_total'], 1)

    def test_get_packager_stats(self):
        ''' Test the get_packager_stats function. '''
        out = self.pkgdb.get_packager_stats('pingou')
        self.assertEqual(
            sorted(out.keys()),
            ['el5', 'el6', 'epel7', 'f19', 'f20', 'f21', 'master', 'output'])
        self.assertEqual(
            sorted(out['master'].keys()),
            ['co-maintainer', 'point of contact'])
        self.assertTrue(out['master']['point of contact'] >= 50)

    def test_get_packagers(self):
        ''' Test the get_packagers function. '''
        out = self.pkgdb.get_packagers('ping*')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packagers'])
        self.assertEqual(out['packagers'], ['pingou'])

    def test_get_packages(self):
        ''' Test the get_packages function. '''
        out = self.pkgdb.get_packages('gua*')

        expected_keys = [
            'acls', 'creation_date', 'description', 'monitor', 'name',
            'review_url', 'status', 'summary', 'upstream_url',
        ]

        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 10)
        self.assertEqual(out['packages'][0]['name'], 'guacamole-client')
        self.assertEqual(sorted(out['packages'][0].keys()), expected_keys)
        self.assertEqual(out['packages'][1]['name'], 'guacamole-common')
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('gua*', branches='el6')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 7)
        self.assertEqual(out['packages'][0]['name'], 'guacamole-common')
        self.assertEqual(sorted(out['packages'][0].keys()), expected_keys)
        self.assertEqual(out['packages'][1]['name'], 'guacamole-ext')
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('gua*', poc='pingou')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 1)
        self.assertEqual(out['packages'][0]['name'], 'guake')
        self.assertEqual(sorted(out['packages'][0].keys()), expected_keys)
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('gua*', status='Retired')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 5)
        self.assertEqual(out['packages'][0]['name'], 'guacd')
        self.assertEqual(sorted(out['packages'][0].keys()), expected_keys)
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('g*', orphaned=True)
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertTrue(len(out['packages']) >= 44)
        self.assertEqual(out['packages'][0]['name'], 'ghex')
        self.assertEqual(sorted(out['packages'][0].keys()), expected_keys)
        #self.assertEqual(out['packages'][1]['name'], 'glom')
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('gua*', poc='pingou', acls=True)
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 1)
        self.assertEqual(out['packages'][0]['name'], 'guake')
        self.assertEqual(sorted(out['packages'][0].keys()), expected_keys)
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('g*', page=2)
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 250)
        self.assertEqual(out['packages'][0]['name'], 'ghc-parameterized-data')
        self.assertEqual(sorted(out['packages'][0].keys()), expected_keys)
        self.assertEqual(out['page'], 2)
        self.assertEqual(out['page_total'], 6)

        out = self.pkgdb.get_packages('g*', count=True)
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertTrue(out['packages'] >= 1340)
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)


class TestPkgdDBAuth(unittest.TestCase):
    ''' Authenticated pkgdb2 tests. '''

    @auth_only
    def setUp(self):
        """ set up data used in the tests.
        setUp is called before each test function execution.
        """
        self.pkgdb = PkgDB(PKGDB_URL, insecure=True)
        self.pkgdb.login(USERNAME, PASSWORD)

    @auth_only
    def test_01_create_collection(self):
        ''' Test the create_collection function. '''
        out = self.pkgdb.create_collection(
            clt_name='Test',
            version=VERSION,
            clt_status='Active',
            branchname=COL_NAME,
            dist_tag='.tst' + COL_NAME[:20],
            git_branch_name='test',
            kojiname='test',
        )

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['Collection "%s" created' % COL_NAME])

        self.assertRaises(
            PkgDBException,
            self.pkgdb.create_collection,
            clt_name='Test',
            version=VERSION,
            clt_status='Active',
            branchname=COL_NAME,
            dist_tag='.tst' + COL_NAME[:20],
            git_branch_name='test',
            kojiname='test',
        )

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['Collection "%s" created' % COL_NAME])

    @auth_only
    def test_02_create_package(self):
        ''' Test the create_package function. '''

        out = self.pkgdb.create_package(
            pkgname=PKG_NAME,
            summary='Test package',
            description='Test package desc',
            review_url='https://bz.com',
            status='Approved',
            shouldopen=False,
            branches=COL_NAME,
            poc='pingou',
            upstream_url='http://guake.org',
            critpath=False)

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['Package created'])

    @auth_only
    def test_03_orphan_packages(self):
        ''' Test the orphan_packages function. '''

        out = self.pkgdb.orphan_packages('guake', ['master', 'el6'])

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['user: pingou changed point of contact of package: guake from: '
             'pingou to: orphan on branch: master',
             'user: pingou changed point of contact of package: guake from: '
             'pingou to: orphan on branch: el6'])

    @auth_only
    def test_04_unorphan_packages(self):
        ''' Test the unorphan_packages function. '''

        out = self.pkgdb.unorphan_packages(
            'guake', ['master', 'el6'], 'pingou')

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['Package guake has been unorphaned on master by pingou',
             'Package guake has been unorphaned on el6 by pingou'])

    @auth_only
    def test_05_retire_packages(self):
        ''' Test the retire_packages function. '''

        out = self.pkgdb.retire_packages('guake', 'master')

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['user: pingou updated package: guake status from: Approved to '
             'Retired on branch: master'])

    @auth_only
    def test_06_unretire_packages(self):
        ''' Test the unretire_packages function. '''

        out = self.pkgdb.unretire_packages('guake', 'master')

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['user: pingou updated package: guake status from: Retired to '
             'Approved on branch: master'])

    @auth_only
    def test_07_update_acl(self):
        ''' Test the update_acl function. '''

        # After un-retiring the package on master, we need to re-set Ralph's
        # pending ACL request
        out = self.pkgdb.update_acl(
            'guake', ['master', 'el6'], 'commit', 'Awaiting Review',
            'ralph')

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['user: pingou set for ralph acl: commit of package: guake from: '
             'Obsolete to: Awaiting Review on branch: master',
             'Nothing to update on branch: el6 for acl: commit'])

        # Check the output when we try to change an ACL to what it is already
        out = self.pkgdb.update_acl(
            'guake', ['master', 'el6'], 'commit', 'Awaiting Review',
            'ralph')

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['Nothing to update on branch: master for acl: commit',
             'Nothing to update on branch: el6 for acl: commit'])

    @auth_only
    def test_08_update_collection_status(self):
        ''' Test the update_collection_status function. '''

        out = self.pkgdb.update_collection_status(COL_NAME, 'EOL')

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['Collection updated from "Active" to "EOL"'])

    @auth_only
    def test_09_update_package_poc(self):
        ''' Test the update_package_poc function. '''

        out = self.pkgdb.update_package_poc(
            'guake', ['master', 'el6'], 'ralph')

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['user: pingou changed point of contact of package: guake from: '
             'orphan to: ralph on branch: master',
             'user: pingou changed point of contact of package: guake from: '
             'pingou to: ralph on branch: el6'])

        out = self.pkgdb.update_package_poc(
            'guake', ['master', 'el6'], 'pingou')

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['user: pingou changed point of contact of package: guake from: '
             'ralph to: pingou on branch: master',
             'user: pingou changed point of contact of package: guake from: '
             'ralph to: pingou on branch: el6'])

    @auth_only
    def test_10_update_critpath(self):
        ''' Test the update_critpath function. '''

        # Check before changing the critpath
        out = self.pkgdb.get_package('guake')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages'])
        self.assertEqual(out['output'], 'ok')
        self.assertEqual(len(out['packages']), 5)
        critpaths = [el['critpath'] for el in out['packages']]
        branches = [el['collection']['branchname'] for el in out['packages']]
        self.assertEqual(
            critpaths,
            [False, False, False, False, False]
        )
        self.assertEqual(
            branches,
            ['master', 'el6', 'f19', 'f20', 'f21']
        )

        out = self.pkgdb.update_critpath(
            'guake', ['master', 'el6'], True)

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['guake: critpath updated on master to True',
             'guake: critpath updated on el6 to True']
        )

        # Check after changing the critpath
        out = self.pkgdb.get_package('guake')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages'])
        self.assertEqual(out['output'], 'ok')
        self.assertEqual(len(out['packages']), 5)
        critpaths = [el['critpath'] for el in out['packages']]
        branches = [el['collection']['branchname'] for el in out['packages']]
        self.assertEqual(
            critpaths,
            [True, True, False, False, False]
        )
        self.assertEqual(
            branches,
            ['master', 'el6', 'f19', 'f20', 'f21']
        )

        out = self.pkgdb.get_package('guake')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages'])
        self.assertEqual(out['output'], 'ok')
        self.assertEqual(len(out['packages']), 5)
        self.assertEqual(
            out['packages'][0]['collection']['branchname'], 'master')
        self.assertEqual(
            out['packages'][0]['package']['name'], 'guake')
        self.assertEqual(
            out['packages'][0]['point_of_contact'], 'pingou')

        out = self.pkgdb.update_critpath(
            'guake', ['master', 'el6'], False)

        self.assertEqual(
            sorted(out.keys()),
            ['messages', 'output'])

        self.assertEqual(out['output'], 'ok')
        self.assertEqual(
            out['messages'],
            ['guake: critpath updated on master to False',
             'guake: critpath updated on el6 to False']
        )

        # Check after reste critpath to False
        out = self.pkgdb.get_package('guake')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages'])
        self.assertEqual(out['output'], 'ok')
        self.assertEqual(len(out['packages']), 5)
        critpaths = [el['critpath'] for el in out['packages']]
        branches = [el['collection']['branchname'] for el in out['packages']]
        self.assertEqual(
            critpaths,
            [False, False, False, False, False]
        )
        self.assertEqual(
            branches,
            ['master', 'el6', 'f19', 'f20', 'f21']
        )


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestPkgdDB))
    suite.addTest(unittest.makeSuite(TestPkgdDBAuth))
    return suite


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pkgdb2 import PkgDB
import unittest
import logging


PKGDB_URL = 'http://127.0.0.1:5000'


class TestPkgdDB(unittest.TestCase):
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

        out = self.pkgdb.get_collections(status='EOL')
        self.assertEqual(
            sorted(out.keys()),
            ['collections', 'output'])
        self.assertTrue(len(out['collections']) >= 24)

    def test_get_package(self):
        ''' Test the get_package function. '''
        out = self.pkgdb.get_package('guake')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages'])
        self.assertEqual(out['output'], 'ok')
        self.assertEqual(len(out['packages']), 15)
        self.assertEqual(
            out['packages'][0]['collection']['branchname'], 'devel')
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
        self.assertEqual(
            out['packages'][0]['point_of_contact'], 'pingou')

        ## We do not support multi-branches yet
        #out = self.pkgdb.get_package('guake', ['f20', 'f19'])
        #self.assertEqual(
            #sorted(out.keys()),
            #['output', 'packages'])
        #self.assertEqual(out['output'], 'ok')
        #self.assertEqual(len(out['packages']), 2)
        #self.assertEqual(
            #out['packages'][0]['collection']['branchname'], 'f20')
        #self.assertEqual(
            #out['packages'][0]['package']['name'], 'guake')
        #self.assertEqual(
            #out['packages'][0]['point_of_contact'], 'pingou')

    def test_get_packager_acls(self):
        ''' Test the get_packager_acls function. '''
        out = self.pkgdb.get_packager_acls('pingou')
        self.assertEqual(
            sorted(out.keys()),
            ['acls', 'output', 'page', 'page_total'])
        self.assertEqual(len(out['acls']), 3000)
        self.assertEqual(out['page_total'], 12)

        out = self.pkgdb.get_packager_acls('pingou', page=3, iterate=False)
        self.assertEqual(
            sorted(out.keys()),
            ['acls', 'output', 'page', 'page_total'])
        self.assertEqual(len(out['acls']), 250)
        self.assertEqual(out['page_total'], 12)

    def test_get_packager_stats(self):
        ''' Test the get_packager_stats function. '''
        out = self.pkgdb.get_packager_stats('pingou')
        self.assertEqual(
            sorted(out.keys()),
            ['EL-5', 'EL-6', 'devel', 'epel7', 'f19', 'f20', 'output'])
        self.assertEqual(
            sorted(out['devel'].keys()),
            ['co-maintainer', 'point of contact'])
        self.assertTrue(out['devel']['point of contact'] >= 60)

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
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 10)
        self.assertEqual(out['packages'][0]['name'], 'guacamole')
        self.assertEqual(
            sorted(out['packages'][0].keys()),
            ['creation_date', 'description', 'name', 'review_url',
             'status', 'summary', 'upstream_url'])
        self.assertEqual(out['packages'][1]['name'], 'guacamole-client')
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('gua*', branches='EL-6')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 7)
        self.assertEqual(out['packages'][0]['name'], 'guacamole-common')
        self.assertEqual(
            sorted(out['packages'][0].keys()),
            ['creation_date', 'description', 'name', 'review_url',
             'status', 'summary', 'upstream_url'])
        self.assertEqual(out['packages'][1]['name'], 'guacamole-ext')
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('gua*', poc='pingou')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 1)
        self.assertEqual(out['packages'][0]['name'], 'guake')
        self.assertEqual(
            sorted(out['packages'][0].keys()),
            ['creation_date', 'description', 'name', 'review_url',
             'status', 'summary', 'upstream_url'])
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('gua*', status='Retired')
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 5)
        self.assertEqual(out['packages'][0]['name'], 'guacamole')
        self.assertEqual(
            sorted(out['packages'][0].keys()),
            ['creation_date', 'description', 'name', 'review_url',
             'status', 'summary', 'upstream_url'])
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('g*', orphaned=True)
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 44)
        self.assertEqual(out['packages'][0]['name'], 'gbirthday')
        self.assertEqual(
            sorted(out['packages'][0].keys()),
            ['creation_date', 'description', 'name', 'review_url',
             'status', 'summary', 'upstream_url'])
        self.assertEqual(out['packages'][1]['name'], 'gconf-cleaner')
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('gua*', poc='pingou', acls=True)
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 1)
        self.assertEqual(out['packages'][0]['name'], 'guake')
        self.assertEqual(
            sorted(out['packages'][0].keys()),
            ['acls', 'creation_date', 'description', 'name', 'review_url',
             'status', 'summary', 'upstream_url'])
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)

        out = self.pkgdb.get_packages('g*', page=2, iterate=False)
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(len(out['packages']), 250)
        self.assertEqual(out['packages'][0]['name'], 'ghasher')
        self.assertEqual(
            sorted(out['packages'][0].keys()),
            ['creation_date', 'description', 'name', 'review_url',
             'status', 'summary', 'upstream_url'])
        self.assertEqual(out['page'], 2)
        self.assertEqual(out['page_total'], 6)

        out = self.pkgdb.get_packages('g*', count=True)
        self.assertEqual(
            sorted(out.keys()),
            ['output', 'packages', 'page', 'page_total'])
        self.assertEqual(out['packages'], 1351)
        self.assertEqual(out['page'], 1)
        self.assertEqual(out['page_total'], 1)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestPkgdDB))
    return suite


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())

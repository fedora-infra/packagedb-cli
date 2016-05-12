====================
Fedora PackageDB-cli
====================

:Author: Pierre-Yves Chibon
:Contact: pingou@fedoraproject.org
:Date: Thu May 12 2016
:Version: 2.13

The `PackageDB-cli` is a commande line interface to the PackageDB of Fedora.

.. contents::

-------
Project
-------

The `PackageDB-cli` was started in May of 2011 to allow user to consult the
package collection and to manage their Access Control List (ACL) using a simple
interface web free interface.

.. _`PackageDB-cli`: https://fedorahosted.org/packagedb-cli

As of 2014, this project has been ported to
`pkgdb2 <https://github.com/fedora-infra/pkgdb2>`_. At this occasion, it is
has been re-written to propose a python module to query pkgdb2 API as well
as the pkgdb2client.cli module containing the command line interface and the
pkgdb2client.admin module containing a command line interface for admins to
interact with `pkgdb2`_.


The tarball of the releases can be found at:
`https://fedorahosted.org/released/packagedb-cli/
<https://fedorahosted.org/released/packagedb-cli/>`_

------------
Installation
------------


Install Prerequisites
~~~~~~~~~~~~~~~~~~~~~

::

  yum install python-fedora


Get and Run the Source
~~~~~~~~~~~~~~~~~~~~~~~~

* Install python-virtualenvwrapper

::

  dnf install python-virtualenvwrapper fedora-cert

* Create the virtual environment

::

  mkvirtualenv pkgdb-cli --system-site-packages

* Activate the virtual environment

::

  workon pkgdb-cli

* Get the project

::

  git clone http://git.fedorahosted.org/git/packagedb-cli.git
  cd packagedb-cli

* Set up the project

::

  python setup.py develop

* Run pkgdb-cli or pkgdb-admin

::

  python pkgdb2client/cli.py
  python pkgdb2client/admin.py


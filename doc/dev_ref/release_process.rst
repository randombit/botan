Release Process and Checklist
========================================

Releases are done quarterly, normally on the second non-holiday Monday
of January, April, July and October. A feature freeze goes into effect
starting 9 days before the release.

.. highlight:: shell

.. note::

   This information is only useful if you are a developer of botan who
   is creating a new release of the library.

Pre Release Testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Do maintainer-mode builds with Clang and GCC to catch any warnings
that should be corrected.

Other checks which are not in CI:

 - Native compile on FreeBSD x86-64
 - Native compile on at least one unusual platform (AIX, NetBSD, ...)
 - Build the website content to detect any Doxygen problems
 - Test many build configurations (using `src/scripts/test_all_configs.py`)
 - Build/test SoftHSM

Confirm that the release notes in ``news.rst`` are accurate and
complete and that the version number in ``version.txt`` is correct.

Tag the Release
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Update the release date in the release notes and change the entry for
the appropriate branch in ``readme.rst`` to point to the new release.

Now check in, and backport changes to the release branch::

  $ git commit readme.rst news.rst -m "Update for 3.8.2 release"
  $ git checkout release-3
  $ git merge master
  $ git tag 3.8.2

Build The Release Tarballs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The release script is ``src/scripts/dist.py`` and must be run from a
git workspace.

  $ src/scripts/dist.py 3.8.2

One useful option is ``--output-dir``, which specifies where the
output will be placed.

Now do a final build/test of the released tarball.

The ``--pgp-key-id`` option is used to specify a PGP keyid. If set,
the script assumes that it can execute GnuPG and will attempt to
create signatures for the tarballs. The default value is ``EFBADFBC``,
which is the official signing key. You can use ``--pgp-key-id=none``
to avoid creating any signature, though official distributed releases
*should not* be released without signatures.

The releases served on the official site are taken from the contents
in a git repository::

  $ git checkout git@botan.randombit.net:/srv/git/botan-releases.git
  $ src/scripts/dist.py 3.8.2 --output-dir=botan-releases
  $ cd botan-releases
  $ sha256sum Botan-3.8.2.tgz >> sha256sums.txt
  $ git add .
  $ git commit -m "Release version 3.8.2"
  $ git push origin master

A cron job updates the live site every 10 minutes.

Push to GitHub
^^^^^^^^^^^^^^^^^^

Don't forget to also push tags::

  $ git push origin --tags release-3 master

Update The Website
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The website content is created by ``src/scripts/website.py``.

The website is mirrored automatically from a git repository which must be updated::

  $ git checkout git@botan.randombit.net:/srv/git/botan-website.git
  $ ./src/scripts/website.py --output-dir botan-website
  $ cd botan-website
  $ git add .
  $ git commit -m "Update for 3.8.2"
  $ git push origin master

Announce The Release
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Send an email to the botan-announce and botan-devel mailing lists
noting that a new release is available.

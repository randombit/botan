Release Process and Checklist
========================================

Releases are done quarterly, normally on the first non-holiday Tuesday
of February, May, August, and November. A feature freeze goes into effect
starting 8 days before the release (ie the Monday of the week prior).

.. highlight:: shell

.. note::

   This information is only useful if you are a developer of botan who
   is creating a new release of the library.

Pre Release Testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In the week prior to a release:

- [ ] Update relevant third party test suites (eg Limbo and BoGo)
- [ ] Do maintainer-mode builds with Clang and GCC to catch any warnings
- [ ] Test build configurations using `src/scripts/test_all_configs.py`
- [ ] Test a few builds on platforms not in CI (eg OpenBSD, FreeBSD, Solaris)

Final Changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When it is time to make the release:

- [ ] Check that the version number in ``src/build-data/version.txt`` is correct.
- [ ] Confirm that the release notes in ``news.rst`` are accurate and complete.

Tag the Release
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- [ ] Update the release date in ``news.rst``
- [ ] Update ``readme.rst`` with the new release URL/date
- [ ] Check in those changes then backport to the release branch::

  $ git commit readme.rst news.rst -m "Update for 3.8.2 release"
  $ git checkout release-3
  $ git merge master
  $ git tag 3.8.2

Build The Release Tarballs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- [ ] Run ``src/scripts/dist.py`` to create the tarball, with the tag as argument::

  $ src/scripts/dist.py 3.8.2

- [ ] Do a final build/test of the generated tarball.

- [ ] Save the generated tarball to the release archive::

  $ cd botan-releases
  $ sha256sum Botan-3.8.2.tar.xz >> sha256sums.txt
  $ git add .
  $ git commit -m "Release version 3.8.2"
  $ git push origin master

Push to GitHub
^^^^^^^^^^^^^^^^^^

- [ ] Push the ``release-3`` and ``master`` branches, including the new tag::

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

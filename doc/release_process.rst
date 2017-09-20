Release Process and Checklist
========================================

.. note::

   This information is only useful if you are a developer of botan who
   is creating a new release of the library.

Pre Release Testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Kick off a Coverity scan a day or so before the planned release.

Do maintainer-mode builds with Clang and GCC to catch any warnings
that should be corrected.

And remember that CI doesn't test everything. In particular, not all
tests run under valgrind or on the qemu cross builds due to time
constraints.  So before release, do a complete build/test cycle:

 - Running under valgrind (remember `--with-valgrind` flag)
 - Using Clang sanitizers (ASan + UbSan)
 - Native or cross compile for Linux aarch64 and ppc64le
 - Native compile on FreeBSD x86-64
 - Native compile on at least one unusual platform (AIX, NetBSD, ...)

Pre Release Checks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Confirm that the release notes in ``news.rst`` are accurate and
complete and that the version number in ``version.txt`` is correct.
Update the release date in the release notes and change the entry for
the appropriate branch in ``readme.rst`` to point to the new release.

Check in these changes (alone, with no other modifications) with a
checkin message along the lines of "Update for X.Y.Z release", then
tag the release with the version in git (eg tag '2.6.13', no prefix).

Build The Release Tarballs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The release script is ``src/scripts/dist.py`` and must be
run from a git workspace.

 $ src/scripts/dist.py 2.6.13

One useful option is ``--output-dir``, which specifies where the
output will be placed.

The ``--pgp-key-id`` option is used to specifiy a PGP keyid. If set,
the script assumes that it can execute GnuPG and will attempt to
create signatures for the tarballs. The default value is ``EFBADFBC``,
which is the official signing key. You can use ``--pgp-key-id=none``
to avoid creating any signature, though official distributed releases
*should not* be released without signatures.

Build The Windows Installer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

On Windows, run ``configure.py`` to setup a build::

 $ python ./configure.py --cc=msvc --cpu=$ARCH --distribution-info=unmodified

After completing the build (and running the tests), use `InnoSetup
<http://www.jrsoftware.org/isinfo.php>`_ to create the installer.  A
InnoSetup script is created from ``src/build-data/innosetup.in`` and
placed in ``build/botan.iss`` by ``configure.py``. Create the
installer either via the InnoSetup GUI by opening the ``iss`` file and
selecting the 'Compile' option, or using the ``iscc`` command line
tool. If all goes well it will produce an executable with a name like
``botan-2.6.13-x86_64.exe``. Sign the installers with GPG.

Update The Website
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The website content is created by ``src/scripts/website.sh``.
Currently refreshing the website is a manual process.

Announce The Release
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Send an email to the botan-announce and botan-devel mailing lists
noting that a new release is available.

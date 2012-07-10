Release Process and Checklist
========================================

First, check that the release notes under ``doc/relnotes`` are
accurate and complete. Then update the datestamp in

 * ``readme.txt``
 * ``botan_version.py``
 * ``doc/download.rst``
 * the release notes

checking in all that the version number is also correct. Check in
these changes (alone, with no other modifications) with a checkin
message along the lines of "Update for X.Y.Z release", then tag the
release with the version in monotone (eg tag '1.10.3', no prefix).

The release script is ``src/build-data/scripts/dist.py`` and runs from
a monotone repository by pulling the revision matching the tag set
previously. For instance::

 $ src/build-data/scripts/dist.py --mtn-db ~/var/mtn/botan.mtn 1.10.3

The ``--mtn-db`` 'option' is mandatory, unless the environmental
variable ``BOTAN_MTN_DB`` is set, in which case that value is used
(unless the option is specified on the command line which overrides
that value).

Another useful option is ``--output-dir``, which specifies where
the output will be placed.

The ``--pgp-key-id`` option is used to specifiy a PGP keyid. If set,
the script assumes that it can execute GnuPG and will attempt to
create signatures for the tarballs. The default value is ``EFBADFBC``,
matching :doc:`the official signing key <pgpkey>`. You can set it to
an empty value (``--pgp-key-id=``) to avoid creating signatures though
official distributed releases *should not* be released without
signatures.

The current botan website is derived entirely from the ReST content in
``docs`` using Sphinx (plus Doxygen generated documentation). A script
called ``mtn-watch`` periodically checks for new updates on the
``net.randombit.botan`` branch (only), and if found regenerates the
site content.

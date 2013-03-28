
Welcome
========================================

Botan is a crypto library for C++ released under the permissive
:doc:`BSD-2 (or FreeBSD) license <license>`.

It provides most any :doc:`cryptographic algorithm <algos>` you might
be looking for, along with :doc:`TLS v1.2 client and server <tls>`,
:doc:`X.509 certs, CRLs, and path validation <x509>`, a
:doc:`pipeline-style message processing system <filters>`,
:doc:`bcrypt password hashing <passhash>`, and other useful things. A
third party open source implementation of `SSHv2
<http://www.netsieben.com/products/ssh/>`_ that uses botan is also
available. In addition to C++ you can use botan from :doc:`Python
<python>` or Perl (both included in tree), or
with `Node.js <https://github.com/justinfreitag/node-botan>`_.

See the :doc:`faq` for a list of common questions and answers.

.. only:: html and website

   See :doc:`download` for information about getting the latest version.

The core of botan is written in C++11 (or C++98 for versions up to and
including 1.10) with no dependencies besides the STL and the rest of
the ISO standard library, but the library also includes optional
modules which make further assumptions about their environment,
providing features such as compression (using zlib or bzip2), entropy
gathering, and secure memory allocation. Assembly implementations of
key algorithms like SHA-1 and multiple precision integer routines for
x86 and x86-64 processors are also included.

It runs on most common operating systems and can be used with a number
of different commercial and open source compilers. The :doc:`build log
<build_log>` contains information about recently tested targets. It
has more than a few :doc:`known users <users>` and is already included
in most major package distributions, including
\
`Fedora <https://admin.fedoraproject.org/pkgdb/acls/name/botan>`_,
`EPEL <http://dl.fedoraproject.org/pub/epel/6/SRPMS/repoview/botan.html>`_ (for RHEL/CentOS),
`Debian <http://packages.debian.org/search?keywords=libbotan>`_,
`Ubuntu <http://packages.ubuntu.com/search?keywords=botan>`_,
`Gentoo <http://packages.gentoo.org/package/botan>`_,
`Arch Linux <http://www.archlinux.org/packages/extra/x86_64/botan/>`_,
`Slackbuild <http://slackbuilds.org/result/?search=Botan>`_,
`FreeBSD <http://www.freshports.org/security/botan>`_,
`NetBSD <ftp://ftp.netbsd.org/pub/pkgsrc/current/pkgsrc/security/botan/README.html>`_,
`Cygwin <http://cygwin.com/packages/botan/>`_,
`MacPorts <http://www.macports.org/ports.php?by=name&substr=botan>`_,
`OpenPKG <http://www.openpkg.org/product/packages/?package=botan>`_, and
`T2 SDE <http://www.t2-project.org/packages/botan.html>`_

It was started as a personal project by `Jack Lloyd
<http://www.randombit.net>`_,who continues to be the maintainer and
release manager. Since the first release in 2001, a number of
individuals and organizations have :doc:`contributed <credits>`.
Check out the :doc:`release notes <relnotes/index>` for more project
history.

If you need help or have questions, send a mail to the `development
mailing list
<http://lists.randombit.net/mailman/listinfo/botan-devel/>`_.
Patches, "philosophical" bug reports, announcements of programs using
the library, and related topics are also welcome. If you find what you
believe to be a bug, please file a ticket in `Bugzilla
<http://bugs.randombit.net/>`_.

A useful reference while reading this manual is the `Doxygen
documentation <http://botan.randombit.net/doxygen>`_.


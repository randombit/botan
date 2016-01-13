Botan: Crypto and TLS for C++11
========================================

Botan (Japanese for peony) is a cryptography library written in C++11
and released under the permissive `Simplified BSD
<http://botan.randombit.net/license.txt>`_ license.

It provides TLS, X.509 certificates, OCSP, ECDSA, AES, GCM, ChaCha20Poly1305,
McEliece, bcrypt, and quite a few other things. It also provides a `botan`
command line tool for various cryptographic operations, the source for which
also helps demonstrate usage of the library.

Development is coordinated on `GitHub <https://github.com/randombit/botan>`_
and contributions are welcome. Read `doc/contributing.rst` for more
about how to contribute.

.. highlight:: none

For all the details on building the library, read the
`users manual <http://botan.randombit.net/manual>`_, but basically::

  $ ./configure.py --help
  $ ./configure.py [probably some options]
  $ make
  $ ./botan-test
  # lots of output...
  Tests all ok
  $ ./botan
  # shows available commands
  $ make install

The library can also be built into a single-file amalgamation for easy
inclusion into external build systems.

If you need help or have questions, send a mail to the
`mailing list <http://lists.randombit.net/mailman/listinfo/botan-devel/>`_
or open a ticket on
`GitHub Issues <https://github.com/randombit/botan/issues>`_. If you
think you've found a security bug, read the
`security page <http://botan.randombit.net/security.html>`_
for contact information and procedures.

The `GitHub wiki <https://github.com/randombit/botan/wiki>`_
and `Doxygen docs <https://botan.randombit.net/doxygen>`_
may also prove useful resources.

In addition to C++, botan has a C89 API specifically designed to be easy
to call from other languages. A Python binding using ctypes is included,
there are also partial bindings for
`Node.js <https://github.com/justinfreitag/node-botan>`_ and
`OCaml <https://github.com/randombit/botan-ocaml>`_ among others.

There is also a third party open source implementation of
`SSHv2 <https://github.com/cdesjardins/cppssh>`_ using the library.

.. image:: https://travis-ci.org/randombit/botan.svg?branch=master
    :target: https://travis-ci.org/randombit/botan

.. image:: https://ci.appveyor.com/api/projects/status/n9f94dljd03j2lce/branch/master?svg=true
    :target: https://ci.appveyor.com/project/randombit/botan/branch/master

.. image:: https://circleci.com/gh/randombit/botan.svg?style=shield
    :target: https://circleci.com/gh/randombit/botan

.. image:: https://botan-ci.kullo.net/badge
    :target: https://botan-ci.kullo.net/

.. image:: https://scan.coverity.com/projects/624/badge.svg
    :target: https://scan.coverity.com/projects/624

.. image:: https://codecov.io/github/randombit/botan/coverage.svg?branch=master
    :target: https://codecov.io/github/randombit/botan

Download
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

See the `change notes <http://botan.randombit.net/news.html>`_ and
`security page <http://botan.randombit.net/security.html>`_

All releases are signed with a
`PGP key <http://botan.randombit.net/pgpkey.txt>`_::

  pub   2048R/EFBADFBC 2004-10-30
        Key fingerprint = 621D AF64 11E1 851C 4CF9  A2E1 6211 EBF1 EFBA DFBC
  uid                  Botan Distribution Key

Botan may already be included in your favorite distribution, such as
`Fedora <https://admin.fedoraproject.org/pkgdb/packages/botan>`_,
`EPEL <http://dl.fedoraproject.org/pub/epel/7/SRPMS/repoview/botan.html>`_ (for RHEL/CentOS),
`Debian <http://packages.debian.org/search?keywords=libbotan>`_,
`Ubuntu <http://packages.ubuntu.com/search?keywords=botan>`_,
`Gentoo <https://packages.gentoo.org/packages/dev-libs/botan>`_,
`Arch <http://www.archlinux.org/packages/community/x86_64/botan/>`_,
`Slackbuild <http://slackbuilds.org/result/?search=Botan>`_,
`FreeBSD ports <http://www.freshports.org/security/botan110>`_, or
`MacPorts <http://www.macports.org/ports.php?by=name&substr=botan>`_.

Current Development Work (1.11)
----------------------------------------

The 1.11 branch is highly recommended, especially for new projects.
Versions 1.11 and later require a working C++11 compiler; GCC 4.8 and
later, Clang 3.4 and later, and MSVC 2013 are regularly tested.

A new development release is made on the first Monday of every month.

The latest development release is
`1.11.26 <http://botan.randombit.net/releases/Botan-1.11.26.tgz>`_
`(sig) <http://botan.randombit.net/releases/Botan-1.11.26.tgz.asc>`_
released on 2016-01-04

Old Stable Series (1.10)
----------------------------------------

The 1.10 branch is the last version of the library written in C++98
and is the most commonly packaged version. It is still supported for
security patches, but all development efforts are focused on 1.11.

The latest 1.10 release is
`1.10.10 <http://botan.randombit.net/releases/Botan-1.10.10.tgz>`_
`(sig) <http://botan.randombit.net/releases/Botan-1.10.10.tgz.asc>`_
released on 2015-08-03

Books and other resources
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You should have some knowledge of cryptography *before* trying to use
the library. This is an area where it is very easy to make mistakes,
and where things are often subtle and/or counterintuitive. Obviously
the library tries to provide things at a high level precisely to
minimize the number of ways things can go wrong, but naive use will
almost certainly not result in a secure system.

Especially recommended are:

- *Cryptography Engineering*
  by Niels Ferguson, Bruce Schneier, and Tadayoshi Kohno

- *Security Engineering -- A Guide to Building Dependable Distributed Systems*
  by Ross Anderson
  (`available online <https://www.cl.cam.ac.uk/~rja14/book.html>`_)

- *Handbook of Applied Cryptography*
  by Alfred J. Menezes, Paul C. Van Oorschot, and Scott A. Vanstone
  (`available online <http://www.cacr.math.uwaterloo.ca/hac/>`_)

If you're doing something non-trivial or unique, you might want to at
the very least ask for review/input on a mailing list such as the
`metzdowd <http://www.metzdowd.com/mailman/listinfo/cryptography>`_ or
`randombit <http://lists.randombit.net/mailman/listinfo/cryptography>`_
crypto lists. And (if possible) pay a professional cryptographer or
security company to review your design and code.

Find Enclosed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TLS/Public Key Infrastructure
----------------------------------------

* TLS and DTLS (v1.0 to v1.2), including using preshared keys
  (TLS-PSK) and passwords (TLS-SRP) and most important extensions,
  such as session tickets, SNI, and ALPN.
* X.509v3 certificates and CRLs
* PKIX certificate path validation
* OCSP requests
* PKCS #10 certificate requests

Public Key Cryptography
----------------------------------------

* RSA signatures and encryption
* DH and ECDH key agreement
* DSA and ECDSA signatures
* Quantum computer resistant McEliece KEM scheme
* GOST-34.10-2001
* ElGamal encryption
* Rabin-Williams signatures
* Nyberg-Rueppel signatures
* Padding schemes OAEP, PSS, PKCS #1 v1.5, X9.31

Ciphers and cipher modes
----------------------------------------

* Authenticated cipher modes EAX, OCB, GCM, SIV, CCM, and ChaCha20Poly1305
* Unauthenticated cipher modes CTR, CBC, XTS, CFB, OFB, and ECB
* AES (including constant time SSSE3 and AES-NI versions)
* AES candidates Serpent, Twofish, MARS, CAST-256, RC6
* Stream ciphers Salsa20/XSalsa20, ChaCha20, and RC4
* DES, 3DES and DESX
* National/telecom block ciphers SEED, KASUMI, MISTY1, GOST 28147
* Other block ciphers including Threefish-512, Blowfish, CAST-128, IDEA,
  Noekeon, TEA, XTEA, RC2, RC5, SAFER-SK
* Large block cipher construction Lion

Hash functions and MACs
----------------------------------------

* SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512
* SHA-3 winner Keccak-1600
* SHA-3 candidate Skein-512
* Authentication codes HMAC, CMAC, Poly1305, SipHash
* RIPEMD-160, Tiger, Whirlpool, GOST 34.11
* Hash function combiners (Parallel and Comb4P)
* Non-cryptographic checksums Adler32, CRC24, CRC32
* Obsolete algorithms MD5, MD4, CBC-MAC, X9.19 DES-MAC
* Deprecated hashes MD2, HAS-160, RIPEMD-128

Other Useful Things
----------------------------------------

* Key derivation functions for passwords, including PBKDF2
* Password hashing functions, including bcrypt and a PBKDF based scheme
* General key derivation functions KDF1 and KDF2 from IEEE 1363
* Format preserving encryption scheme FE1
* Threshold secret sharing
* RFC 3394 keywrapping
* Rivest's all or nothing transform

Recommended Algorithms
----------------------------------------

If your application is protecting network traffic, seriously consider
using TLS v1.2 as a pre built, standard and well studied protocol.

Otherwise, if you simply *must* do something custom, the developers
currently recommend using:

* Message encryption: AES or Serpent in GCM mode, or ChaCha20Poly1305

* General hash functions: SHA-256 or SHA-384

* Message authentication: HMAC with SHA-256

* Public Key Encryption: RSA, 2048+ bit keys, with OAEP and SHA-256

* Public Key Signatures: RSA, 2048+ bit keys with PSS and SHA-512,
  or ECDSA with P-256/SHA-256 or P-384/SHA-384

* Key Agreement: ECDH P-256 or Curve25519, with KDF2(SHA-256)
  Or McEliece if you are concerned about attacks by quantum computers.

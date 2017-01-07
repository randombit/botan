Botan: Crypto and TLS for C++11
========================================

Botan (Japanese for peony) is a cryptography library written in C++11
and released under the permissive `Simplified BSD
<https://botan.randombit.net/license.txt>`_ license.

Botan's goal is to be the best option for cryptography in new C++ code by
offering the tools necessary to implement a range of practical systems, such as
TLS/DTLS, PKIX certificate handling, PKCS#11 and TPM hardware support, password
hashing, and post quantum crypto schemes. Find the full feature list below.

Development is coordinated on `GitHub <https://github.com/randombit/botan>`_
and contributions are welcome (read `doc/contributing.rst` for more info).

If you need help, open a GitHub issue, email the `mailing list
<http://lists.randombit.net/mailman/listinfo/botan-devel/>`_, or try
the botan `gitter.im <https://gitter.im/libbotan/Chat>`_ channel.

If you think you've found a security bug, read the `security page
<https://botan.randombit.net/security.html>`_ for contact information
and procedures.

.. highlight:: none

For all the details on building the library, read the
`users manual <https://botan.randombit.net/manual>`_, but basically::

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

In addition to C++, botan has a C89 API specifically designed to be easy
to call from other languages. A Python binding using ctypes is included.

Continuous integration status
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. image:: https://travis-ci.org/randombit/botan.svg?branch=master
    :target: https://travis-ci.org/randombit/botan
    :alt: Travis CI status

.. image:: https://ci.appveyor.com/api/projects/status/n9f94dljd03j2lce/branch/master?svg=true
    :target: https://ci.appveyor.com/project/randombit/botan/branch/master
    :alt: AppVeyor CI status

.. image:: https://circleci.com/gh/randombit/botan.svg?style=shield
    :target: https://circleci.com/gh/randombit/botan
    :alt: CircleCI status

.. image:: https://botan-ci.kullo.net/badge
    :target: https://botan-ci.kullo.net/
    :alt: Kullo CI status

Static analyzer status
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. image:: https://codecov.io/github/randombit/botan/coverage.svg?branch=master
    :target: https://codecov.io/github/randombit/botan
    :alt: Code coverage report

.. image:: https://scan.coverity.com/projects/624/badge.svg
    :target: https://scan.coverity.com/projects/624
    :alt: Coverity results

.. image:: https://sonarqube.com/api/badges/gate?key=botan
    :target: https://sonarqube.com/dashboard/index/botan
    :alt: Sonarqube analysis

Download
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

See the `change notes <https://botan.randombit.net/news.html>`_ and
`security page <https://botan.randombit.net/security.html>`_

All releases are signed with a
`PGP key <https://botan.randombit.net/pgpkey.txt>`_::

  pub   2048R/EFBADFBC 2004-10-30
        Key fingerprint = 621D AF64 11E1 851C 4CF9  A2E1 6211 EBF1 EFBA DFBC
  uid                  Botan Distribution Key

Some distributions such as Arch, Fedora and Debian include packages
for Botan. However these are often out of date; using the latest
source release is recommended.

Current Stable Release
----------------------------------------

Version 2 requires a C++11 compiler; GCC 4.8 and later, Clang 3.5 and
later, and MSVC 2015 are regularly tested.

The latest 2.x release is
`2.0.0 <https://botan.randombit.net/releases/Botan-2.0.0.tgz>`_
`(sig) <https://botan.randombit.net/releases/Botan-2.0.0.tgz.asc>`_
released on 2017-01-06

Old Stable Release
----------------------------------------

The 1.10 branch is the last version of the library written in C++98 and is still
the most commonly packaged version. It is no longer supported except for
critical security updates (with all support ending on 2018-1-1), and the
developers do not recommend its use anymore.

The latest 1.10 release is
`1.10.14 <https://botan.randombit.net/releases/Botan-1.10.14.tgz>`_
`(sig) <https://botan.randombit.net/releases/Botan-1.10.14.tgz.asc>`_
released on 2016-11-28

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

Transport Layer Security (TLS) Protocol
----------------------------------------

* TLS v1.0, v1.1, and v1.2. The broken SSLv3 protocol is no longer supported.
* DTLS v1.0 and v1.2 are adaptations of TLS to datagram operation.
* Extensions include session tickets, SNI, ALPN, OCSP staple requests (client
  side only right now), encrypt-then-mac CBC, and extended master secret.
* Supports authentication using preshared keys (PSK) or passwords (SRP)
* Supports record encryption with ChaCha20Poly1305, AES/OCB, AES/GCM, AES/CCM,
  Camellia/GCM, and legacy CBC ciphersuites with AES, Camellia, SEED, or 3DES.
* Key exchange using Diffie-Hellman, ECDH, RSA, or CECPQ1

Public Key Infrastructure
----------------------------------------

* X.509v3 certificates and CRL creation and handling
* PKIX certificate path validation, including name constraints.
* OCSP request creation and response handling
* PKCS #10 certificate request generation and processing
* SQL database backed certificate store

Public Key Cryptography
----------------------------------------

* RSA signatures and encryption
* DH and ECDH key agreement
* Signature schemes ECDSA, DSA, ECGDSA, ECKCDSA, and GOST 34.10-2001
* Post-quantum signature scheme XMSS
* Post-quantum key agreement schemes McEliece and NewHope
* ElGamal encryption
* Padding schemes OAEP, PSS, PKCS #1 v1.5, X9.31

Ciphers, hashes, MACs, and checksums
----------------------------------------

* Authenticated cipher modes EAX, OCB, GCM, SIV, CCM, and ChaCha20Poly1305
* Cipher modes CTR, CBC, XTS, CFB, and OFB
* Block ciphers AES, Serpent, Blowfish, Twofish, Threefish-512,
  DES/3DES, Noekeon, IDEA, CAST-128, XTEA, SEED, KASUMI, GOST 28147,
  MISTY1, Lion, CAST-256
* Stream ciphers ChaCha20, Salsa20/XSalsa20, SHAKE-128, and RC4
* Hash functions SHA-1, SHA-2, SHA-3, RIPEMD-160, Skein-512,
  BLAKE2b, Tiger, Whirlpool, GOST 34.11, MD5, MD4
* Hash function combiners Parallel and Comb4P
* Authentication codes HMAC, CMAC, Poly1305, SipHash, GMAC, CBC-MAC, X9.19 DES-MAC
* Non-cryptographic checksums Adler32, CRC24, and CRC32

Other Useful Things
----------------------------------------

* Full C++ PKCS #11 API wrapper
* Interfaces for TPM v1.2 device access
* Simple compression API wrapping zlib, bzip2, and lzma libraries
* RNG wrappers for system RNG and hardware RNGs
* HMAC_DRBG and entropy collection system for userspace RNGs
* PBKDF2 password based key derivation
* Password hashing function bcrypt and passhash9 (custom PBKDF scheme)
* SRP-6a password authenticated key exchange
* Key derivation functions including HKDF, KDF2, SP 800-108, SP 800-56C
* Format preserving encryption scheme FE1
* Threshold secret sharing
* RFC 3394 AES key wrap

Recommended Algorithms
----------------------------------------

* For encryption of network traffic use TLS v1.2
* Packet encryption: AES-256/GCM, AES-256/OCB, Serpent/OCB, or ChaCha20Poly1305
* General hash function: BLAKE2b, SHA-2, SHA-3, or Skein-512
* Message authentication or PRF: HMAC with SHA-256
* Key derivation function: KDF2 or HKDF
* Public Key Encryption: RSA, 2048+ bit keys, with OAEP/SHA-256
* Public Key Signatures: RSA, 2048+ bit keys with PSS/SHA-512,
  or ECDSA using P-256/SHA-256 or P-521/SHA-512
* Key Agreement: ECDH using P-256 or X25519. If you are concerned
  about quantum computers, combine ECC with NewHope.

Code coverage map
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. image:: https://codecov.io/gh/randombit/botan/graphs/tree.svg

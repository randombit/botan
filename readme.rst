Botan
========================================

Botan (Japanese for peony flower) is a cryptography library released under the
permissive `Simplified BSD <https://botan.randombit.net/license.txt>`_ license.

Botan's `goal <https://botan.randombit.net/handbook/goals.html>`_
is to be the best option for production cryptography by offering the tools
necessary to implement a range of practical systems, such as TLSv1.3, X.509 PKI,
modern AEAD ciphers, support for PKCS#11 and TPM hardware, memory-hard password
hashing, and post quantum cryptography. All of this is covered by an extensive
test suite, including an automated system for detecting side channels. The
modular build system allows enabling or disabling features in a fine-grained way,
and amalgamation builds are also supported.

It comes out of the box with C++, C, and Python APIs, and several other `language
bindings <https://github.com/randombit/botan/wiki/Language-Bindings>`_ are available.
The library is accompanied by a featureful `command line interface
<https://botan.randombit.net/handbook/cli.html>`_. Consult the `documentation
<https://botan.randombit.net/handbook>`_ for more information.

Development is coordinated on `GitHub <https://github.com/randombit/botan>`__ and
contributions are welcome. If you need help, please open an issue on `GitHub
<https://github.com/randombit/botan/issues>`__. If you think you have found a
security issue, see the `security page <https://botan.randombit.net/security.html>`_
for contact information.

|ci_status| |nightly_ci_status| |coverage| |ossfuzz| |repo| |ossf| |cii|

.. |ci_status| image:: https://github.com/randombit/botan/actions/workflows/ci.yml/badge.svg?branch=master
    :target: https://github.com/randombit/botan/actions/workflows/ci.yml
    :alt: CI status

.. |nightly_ci_status| image:: https://github.com/randombit/botan/actions/workflows/nightly.yml/badge.svg?branch=master
    :target: https://github.com/randombit/botan/actions/workflows/nightly.yml
    :alt: nightly CI status

.. |coverage| image:: https://img.shields.io/coverallsCoverage/github/randombit/botan?branch=master
    :target: https://coveralls.io/github/randombit/botan
    :alt: Coverage report

.. |ossfuzz| image:: https://oss-fuzz-build-logs.storage.googleapis.com/badges/botan.svg
    :target: https://oss-fuzz.com/coverage-report/job/libfuzzer_asan_botan/latest
    :alt: OSS-Fuzz status

.. |repo| image:: https://repology.org/badge/tiny-repos/botan.svg
    :target: https://repology.org/project/botan/versions
    :alt: Packaging status

.. |ossf| image:: https://api.securityscorecards.dev/projects/github.com/randombit/botan/badge
    :target: https://securityscorecards.dev/viewer/?uri=github.com/randombit/botan
    :alt: OSSF Scorecard

.. |cii| image:: https://bestpractices.coreinfrastructure.org/projects/531/badge
    :target: https://bestpractices.coreinfrastructure.org/projects/531
    :alt: CII Best Practices statement

Releases
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All releases are signed with a `PGP key <https://botan.randombit.net/pgpkey.txt>`_.
See the `release notes <https://botan.randombit.net/news.html>`_ for
what's new.

Botan is also available through most `distributions
<https://github.com/randombit/botan/wiki/Distros>`_ such as Fedora,
Debian, Arch and Homebrew.

Botan3
--------

New minor releases of Botan3 are made quarterly, normally on the first Tuesday of
February, May, August, and November.

The latest release in the Botan3 series is
`3.7.1 <https://botan.randombit.net/releases/Botan-3.7.1.tar.xz>`_
`(sig) <https://botan.randombit.net/releases/Botan-3.7.1.tar.xz.asc>`__,
released on 2025-02-05.

Botan2
--------

Botan2 has, as of 2025-1-1, reached end of life. No further releases are expected.

The latest release in the Botan2 series is
`2.19.5 <https://botan.randombit.net/releases/Botan-2.19.5.tar.xz>`_
`(sig) <https://botan.randombit.net/releases/Botan-2.19.5.tar.xz.asc>`__,
released on 2024-07-08.

Find Enclosed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Transport Layer Security (TLS) Protocol
----------------------------------------

* TLS v1.2/v1.3, and DTLS v1.2
* Supported extensions include session tickets, SNI, ALPN, OCSP stapling,
  encrypt-then-mac CBC, and extended master secret.
* Supports authentication using certificates or preshared keys (PSK)
* Supports record encryption with modern AEAD modes as well as legacy CBC ciphersuites.
* TLS 1.3 supports hybrid post-quantum key exchange using ML-KEM or FrodoKEM

Public Key Infrastructure
----------------------------------------

* X.509v3 certificates and CRL creation and handling
* PKIX certificate path validation, including name constraints
* OCSP request creation and response handling
* PKCS #10 certificate request generation and processing
* Access to Windows, macOS and Unix system certificate stores
* SQL database backed certificate store

Public Key Cryptography
----------------------------------------

* RSA signatures and encryption
* DH, ECDH, X25519 and X448 key agreement
* Elliptic curve signature schemes ECDSA, Ed25519, Ed448, ECGDSA, ECKCDSA, SM2
* Post-quantum signature schemes ML-DSA (Dilithium), SLH-DSA (SPHINCS+), HSS/LMS, XMSS
* Post-quantum key encapsulation schemes ML-KEM (Kyber), FrodoKEM, Classic McEliece

Ciphers, hashes, MACs, and checksums
----------------------------------------

* Authenticated cipher modes EAX, OCB, GCM, SIV, CCM, (X)ChaCha20Poly1305
* Cipher modes CTR, CBC, XTS, CFB, OFB
* Block ciphers AES, ARIA, Blowfish, Camellia, CAST-128, DES/3DES, IDEA,
  SEED, Serpent, SHACAL2, SM4, Threefish-512, Twofish
* Stream ciphers (X)ChaCha20, (X)Salsa20, RC4
* Hash functions SHA-1, SHA-2, SHA-3, RIPEMD-160, BLAKE2b/BLAKE2s, Skein-512, SM3, Whirlpool
* Password hashing schemes Argon2, Scrypt, bcrypt, and PBKDF2
* Authentication codes HMAC, CMAC, Poly1305, KMAC, SipHash, GMAC
* Non-cryptographic checksums Adler32, CRC24, CRC32

Other Useful Things
----------------------------------------

* Full C++ PKCS #11 API wrapper
* Interfaces for TPM v2.0 device access
* Simple compression API wrapping zlib, bzip2, and lzma libraries
* RNG wrappers for system RNG, ESDM and hardware RNGs
* HMAC_DRBG and entropy collection system for userspace RNGs
* SRP-6a password authenticated key exchange
* Key derivation functions including HKDF, KDF2, SP 800-108, SP 800-56A, SP 800-56C
* HOTP and TOTP algorithms
* Format preserving encryption scheme FE1
* Threshold secret sharing
* Roughtime client
* Zfec compatible forward error correction encoding
* Encoding schemes including hex, base32, base64 and base58
* NIST key wrapping
* Boost.Asio compatible TLS client stream

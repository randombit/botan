Botan: Crypto and TLS for Modern C++
========================================

Botan (Japanese for peony flower) is a C++ cryptography library released under the
permissive `Simplified BSD <https://botan.randombit.net/license.txt>`_ license.

Botan's goal is to be the best option for cryptography in C++ by offering the
tools necessary to implement a range of practical systems, such as TLS protocol,
X.509 certificates, modern AEAD ciphers, PKCS#11 and TPM hardware support,
password hashing, and post quantum crypto schemes. A Python binding is included,
and several other `language bindings
<https://github.com/randombit/botan/wiki/Language-Bindings>`_ are available.
The library is accompanied by a featureful
`command line interface <https://botan.randombit.net/handbook/cli.html>`_.

See the `documentation <https://botan.randombit.net/handbook>`_ for more
information about included features.

Development is coordinated on `GitHub <https://github.com/randombit/botan>`__
and contributions are welcome. If you need help, please open an issue on
`GitHub <https://github.com/randombit/botan/issues>`__.

If you think you have found a security issue, see the `security page
<https://botan.randombit.net/security.html>`_ for contact information.

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

The latest release from the Botan3 release series is
`3.5.0 <https://botan.randombit.net/releases/Botan-3.5.0.tar.xz>`_
`(sig) <https://botan.randombit.net/releases/Botan-3.5.0.tar.xz.asc>`__,
released on 2024-07-08.

The latest release from the Botan2 release series is
`2.19.5 <https://botan.randombit.net/releases/Botan-2.19.5.tar.xz>`_
`(sig) <https://botan.randombit.net/releases/Botan-2.19.5.tar.xz.asc>`__,
released on 2024-07-08.

All releases are signed with a `PGP key <https://botan.randombit.net/pgpkey.txt>`_.
See the `release notes <https://botan.randombit.net/news.html>`_ for
what is new. Botan is also available through most
`distributions <https://github.com/randombit/botan/wiki/Distros>`_
such as Fedora, Debian, Arch and Homebrew.

Find Enclosed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Transport Layer Security (TLS) Protocol
----------------------------------------

* TLS v1.2/v1.3, and DTLS v1.2
* Supported extensions include session tickets, SNI, ALPN, OCSP stapling,
  encrypt-then-mac CBC, and extended master secret.
* Supports authentication using certificates or preshared keys (PSK)
* Supports record encryption with modern AEAD modes as well as legacy CBC ciphersuites.
* TLS 1.3 supports post-quantum key exchange with Kyber and FrodoKEM

Public Key Infrastructure
----------------------------------------

* X.509v3 certificates and CRL creation and handling
* PKIX certificate path validation, including name constraints.
* OCSP request creation and response handling
* PKCS #10 certificate request generation and processing
* Access to Windows, macOS and Unix system certificate stores
* SQL database backed certificate store

Public Key Cryptography
----------------------------------------

* RSA signatures and encryption
* DH and ECDH key agreement
* Signature schemes ECDSA, DSA, Ed25519, Ed448, ECGDSA, ECKCDSA, SM2, GOST 34.10
* Post-quantum signature schemes Dilithium, HSS/LMS, SPHINCS+, XMSS
* Post-quantum key agreement schemes McEliece, Kyber, and FrodoKEM
* ElGamal encryption
* Padding schemes OAEP, PSS, PKCS #1 v1.5, X9.31

Ciphers, hashes, MACs, and checksums
----------------------------------------

* Authenticated cipher modes EAX, OCB, GCM, SIV, CCM, (X)ChaCha20Poly1305
* Cipher modes CTR, CBC, XTS, CFB, OFB
* Block ciphers AES, ARIA, Blowfish, Camellia, CAST-128, DES/3DES, IDEA,
  Lion, SEED, Serpent, SHACAL2, SM4, Threefish-512, Twofish
* Stream ciphers (X)ChaCha20, (X)Salsa20, SHAKE-128, RC4
* Hash functions SHA-1, SHA-2, SHA-3, MD5, RIPEMD-160, BLAKE2b/BLAKE2s,
  Skein-512, SM3, Streebog, Whirlpool
* Password hashing schemes PBKDF2, Argon2, Scrypt, bcrypt
* Authentication codes HMAC, CMAC, Poly1305, KMAC, SipHash, GMAC, X9.19 DES-MAC
* Non-cryptographic checksums Adler32, CRC24, CRC32

Other Useful Things
----------------------------------------

* Full C++ PKCS #11 API wrapper
* Interfaces for TPM v1.2 device access
* Simple compression API wrapping zlib, bzip2, and lzma libraries
* RNG wrappers for system RNG and hardware RNGs
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

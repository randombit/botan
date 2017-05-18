Projects
========================================

Feel free to take one of these on if it interests you. Before starting
out on something, send an email to the dev list or open a discussion
ticket on GitHub to make sure you're on the right track.

Request a new feature by opening a pull request to update this file.

Ciphers, Hashes, PBKDF
----------------------------------------

* Bitsliced AES or Camellia
* Compressed tables for AES
* AES using vector permutes for NEON or AltiVec
* Camellia using AES-NI
* Serpent using AVX2 or SSSE3/pshufb
* ChaCha20 using AVX2, NEON
* XSalsa20-Poly1305 AEAD compatible with NaCl
* ARIA block cipher (RFCs 5794 and 6209)
* ASCON 1.2 (CAESAR)
* NORX-64 3.0 (CAESAR)
* scrypt PBKDF
* Argon2 PBKDF (draft-irtf-cfrg-argon2)
* Skein-MAC
* Extend Cascade_Cipher to support arbitrary number of ciphers

Public Key Crypto, Math
----------------------------------------

* Curves for pairings (BN-256 is widely implemented)
* Identity based encryption
* SPHINCS-256
* Ed25519 / EdDSA (GH #283)
* Ed448-Goldilocks
* FHMQV
* Support mixed hashes and non-empty param strings in OAEP
* wNAF ECC point multiply
* Recover ECDSA public key from signature/message pair (GH #664)
* Fast new implementations/algorithms for ECC point operations,
  Montgomery multiplication, multi-exponentiation, ...
* Some PK operations, especially RSA, have extensive computations per
  operation setup but many of the computed values depend only on the
  key and could be shared across operation objects.

External Providers, Hardware Support
----------------------------------------

* Access to system certificate stores (Windows, OS X)
* Extend OpenSSL provider (DH, HMAC, CMAC, GCM)
* Support using BoringSSL instead of OpenSSL or LibreSSL
* /dev/crypto provider (ciphers, hashes)
* Windows CryptoAPI provider (ciphers, hashes, RSA)
* Apple CommonCrypto
* ARMv8-A crypto extensions (AES, SHA-2)
* POWER8 crypto extensions (AES, SHA-2)
* Better TPM support: NVRAM, PCR measurements, sealing
* Intel SGX support

TLS
----------------------------------------

* Make DTLS support optional at build time
* Improve/optimize DTLS defragmentation and retransmission
* Implement logging callbacks for TLS
* Make TLS v1.0 and v1.1 optional at build time
* Make RSA optional at build time
* Make finite field DH optional at build time
* TLS OCSP stapling (RFC 6066)
* Authentication using TOFU (sqlite3 storage)
* Certificate pinning (using TACK?)
* Certificate Transparency
* TLS supplemental authorization data (RFC 4680, RFC 5878)
* OpenPGP authentication (RFC 5081)
* DTLS-SCTP (RFC 6083)
* Perspectives (http://perspectives-project.org/)
* Support for server key stored in TPM or PKCS #11

PKIX
----------------------------------------

* Further tests of validation API (see GH #785)
* Test suite for validation of 'real world' cert chains (GH #611)
* Improve output of X509_Certificate::to_string
  This is a free-form string for human consumption so the only constraints
  are being informative and concise. (GH #656)
* X.509 policy constraints
* OCSP responder logic
* X.509 attribute certificates (RFC 5755)
* Support generating/verifying XMSS certificates
* Roughtime client (https://roughtime.googlesource.com/roughtime/),
  requires Ed25519

New Protocols / Formats
----------------------------------------

* NaCl compatible cryptobox functions
* Off-The-Record v3 https://otr.cypherpunks.ca/
* Some useful subset of OpenPGP
  - Subset #1: symmetrically encrypted files

    Not aiming to process arbitrary OpenPGP, but rather produce
    something that happens to be readable by `gpg` and is relatively
    simple to process for decryption. Require a 128-bit block cipher
    and MDC packet.

  - Subset #2: Process OpenPGP public keys
  - Subset #3: Verification of OpenPGP signatures

Cleanups
-----------

* Split ffi.cpp and test_ffi.cpp into multiple files

Compat Headers
----------------

* Write an OpenSSL-compatible TLS API stub so existing applications
  can be converted more easily. Would require some networking code
  since the OpenSSL API handles both crypto and IO. Use Asio, since it
  is expected to be the base of future C++ standard network library.

FFI and Bindings
----------------------------------------

* Expose compression
* Expose more of X.509 (CRLs, OCSP, cert signing, etc)
* Expose TLS
* Write a CLI or HTTPS client in Python

Library Infrastructure
----------------------------------------

* Guarded integer type to prevent overflow bugs
* Add logging callbacks
* Add latency tracing framework

Build/Test
----------------------------------------

* Code signing for Windows installers
* Test runner python script that captures backtraces and other
  debug info during CI

FIPS 140 Build
---------------------------------------

* Special build policy that disables all builtin crypto impls, then provides new
  FIPS 140 versions implemented using just calls to the OpenSSL FIPS module API
  plus wrapping the appropriate functions for self-tests and so on. This creates a
  library in FIPS 140 validated form (since there is no 'crypto' anymore from
  Botan, just the ASN.1 parser, TLS library, PKI etc all of which FIPS 140 does
  not care about) without the enourmous hassle and expense of actually having to
  maintain a FIPS validation on Botan. Email Jack if you are interested in this.

CLI
----------------------------------------

* Change `tls_server` to be a tty<->socket app, like `tls_client` is,
  instead of a bogus echo server.
* `encrypt` / `decrypt` tools providing password and/or public key
  based file encryption
* Make help output more helpful

Documentation
----------------------------------------

* X.509 certs, path validation
* Specific docs covering one major topic (RSA, ECDSA, AES/GCM, ...)
* Some howto style docs (setting up CA, ...)
* List each cipher, hash, etc, describe its usage, and give the
  header file and BOTAN_HAS_X macro associated with it.

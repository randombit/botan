Projects
========================================

Feel free to take one of these on if it interests you. Before starting
out on something, send an email to the dev list or open a discussion
ticket on GitHub to make sure you're on the right track.

Request a new feature by opening a pull request to update this file.

Ciphers, Hashes, PBKDF
----------------------------------------

* Stiched AES-NI GCM mode
* Bitsliced AES or Camellia
* Compressed tables for AES
* AES using vector permutes for NEON
* Camellia using AES-NI
* Serpent using AVX2 or SSSE3/pshufb
* ChaCha20 using AVX2, NEON
* ASCON 1.2 (CAESAR)
* NORX-64 3.0 (CAESAR)
* Argon2 PBKDF (draft-irtf-cfrg-argon2)
* Skein-MAC
* PMAC
* SIV-PMAC
* Extend Cascade_Cipher to support arbitrary number of ciphers
* EME* tweakable block cipher (https://eprint.iacr.org/2004/125.pdf)
* FFX format preserving encryption (NIST 800-38G)

Public Key Crypto, Math
----------------------------------------

* Abstract representation of ECC point elements to allow specific
  implementations of the field arithmetic depending upon the curve.
* Curves for pairings (BN-256 is widely implemented)
* Identity based encryption
* BBS group signatures
* Paillier homomorphic cryptosystem
* Socialist Millionaires Protocol
* Hashing onto an elliptic curve (draft-irtf-cfrg-hash-to-curve)
* OPAQUE PAKE (draft-krawczyk-cfrg-opaque)
* SPHINX password store (https://eprint.iacr.org/2018/695)
* SPAKE2+ (draft-irtf-cfrg-spake2)
* SPHINCS-256
* X448 and Ed448
* FHMQV
* Use GLV decomposition to speed up secp256k1 operations
* Recover ECDSA public key from signature/message pair (GH #664)

Utility Functions
------------------

* base58 encoding

Multiparty Protocols
----------------------

* Distributed key generation for DL, RSA
* Threshold signing, decryption

External Providers, Hardware Support
----------------------------------------

* Access to system certificate stores (Windows, OS X)
* Extend OpenSSL provider (DH, HMAC, CMAC, GCM)
* Support using BoringSSL instead of OpenSSL or LibreSSL
* /dev/crypto provider (ciphers, hashes)
* Windows CryptoNG provider (ciphers, hashes)
* Apple CommonCrypto
* POWER8 crypto extensions (SHA-2, GCM)
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

New Protocols / Formats
----------------------------------------

* ORAM (Circuit-ORAM, Path-ORAM, ??)
* Roughtime client (https://roughtime.googlesource.com/roughtime/)
* PKCS7 / Cryptographic Message Syntax
* PKCS12 / PFX
* NaCl compatible cryptobox functions
* Off-The-Record v3 https://otr.cypherpunks.ca/
* Fernet symmetric encryption (https://cryptography.io/en/latest/fernet/)
* Useful OpenPGP subset 1: symmetrically encrypted files.
  Not aiming to process arbitrary OpenPGP, but rather produce
  something that happens to be readable by `gpg` and is relatively
  simple to process for decryption. Require a 128-bit block cipher and
  MDC packet.
* Useful OpenPGP subset 2: Process OpenPGP public keys
* Useful OpenPGP subset 3: Verification of OpenPGP signatures

Cleanups
-----------

* Split test_ffi.cpp into multiple files

Compat Headers
----------------

* OpenSSL compatible API headers: EVP, TLS, certificates, etc

FFI and Bindings
----------------------------------------

* Expose NewHope and CECPQ1
* Expose compression
* Expose more of X.509 (CRLs, PKCS10, OCSP, cert signing, etc)
* Expose TLS
* Expose TOTP/HOTP
* Expose deterministic PRNG
* Write a CLI or HTTPS client in Python

Library Infrastructure
----------------------------------------

* Guarded integer type to prevent overflow bugs
* Add logging callbacks
* Add latency tracing framework

Build/Test
----------------------------------------

* Create Docker image for Travis that runs 16.04 and has all
  the tools we need pre-installed.
* Code signing for Windows installers
* Test runner python script that captures backtraces and other
  debug info during CI
* Run the TPM tests against an emulator
  (https://github.com/PeterHuewe/tpm-emulator)
* Add clang-tidy, clang-analyzer, cppcheck to CI

FIPS 140 Build
---------------------------------------

* Special build policy that disables all builtin crypto impls, then provides new
  FIPS 140 versions implemented using just calls to the OpenSSL FIPS module API
  plus wrapping the appropriate functions for self-tests and so on. This creates a
  library in FIPS 140 validated form (since there is no 'crypto' anymore from
  Botan, just the ASN.1 parser, TLS library, PKI etc all of which FIPS 140 does
  not care about) without the enormous hassle and expense of actually having to
  maintain a FIPS validation on Botan. Email Jack if you are interested in this.

CLI
----------------------------------------

* Change `tls_server` to be a tty<->socket app, like `tls_client` is,
  instead of a bogus echo server.
* `encrypt` / `decrypt` tools providing password based file encryption
* Clone of `minisign` signature utility
* Implementation of `tlsdate`

Documentation
----------------------------------------

* X.509 certs, path validation
* Specific docs covering one major topic (RSA, ECDSA, AES/GCM, ...)
* Some howto style docs (setting up CA, ...)

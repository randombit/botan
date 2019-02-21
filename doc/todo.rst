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
* Poly1305 using AVX2
* ASCON 1.2 (CAESAR)
* NORX-64 3.0 (CAESAR)
* Argon2 PBKDF (draft-irtf-cfrg-argon2)
* Skein-MAC
* PMAC
* SIV-PMAC
* GCM-SIV (draft-irtf-cfrg-gcmsiv)
* Extend Cascade_Cipher to support arbitrary number of ciphers
* EME* tweakable block cipher (https://eprint.iacr.org/2004/125.pdf)
* FFX format preserving encryption (NIST 800-38G)
* SHA-512 using BMI2+AVX2
* Constant time DES using BMI2
* Threefish-1024
* SIMD evaluation of SHA-2 and SHA-3 compression functions

Public Key Crypto, Math
----------------------------------------

* Abstract representation of ECC point elements to allow specific
  implementations of the field arithmetic depending upon the curve.
* Use NAF (joint sparse form) for ECC multi-exponentiation
* Curves for pairings (BN-256 is widely implemented)
* Identity based encryption
* BBS group signatures
* Paillier homomorphic cryptosystem
* Socialist Millionaires Protocol
* Hashing onto an elliptic curve (draft-irtf-cfrg-hash-to-curve)
* OPAQUE PAKE (draft-krawczyk-cfrg-opaque)
* SPHINX password store (https://eprint.iacr.org/2018/695)
* SPAKE2+ (draft-irtf-cfrg-spake2)
* SPHINCS+
* Dilithium lattice based signatures
* Kyber lattice based KEM
* X448 and Ed448
* FHMQV
* Use GLV decomposition to speed up secp256k1 operations

Utility Functions
------------------

* Add a memory span type
* Make Memory_Pool more concurrent (currently uses a global lock)

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
* Extend Apple CommonCrypto provider (HMAC, CMAC, RSA, ECDSA, ECDH)
* POWER8 crypto extensions (SHA-2, GCM)
* Better TPM support: NVRAM, PCR measurements, sealing
* Intel SGX support
* Support Intel QuickAssist accelerator cards

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
* Certificate Management Protocol (RFC 5273); requires CMS
* Fernet symmetric encryption (https://cryptography.io/en/latest/fernet/)
* Useful OpenPGP subset 1: symmetrically encrypted files.
  Not aiming to process arbitrary OpenPGP, but rather produce
  something that happens to be readable by `gpg` and is relatively
  simple to process for decryption. Require AEAD mode (EAX/OCB).
* Useful OpenPGP subset 2: Process OpenPGP public keys
* Useful OpenPGP subset 3: Verification of OpenPGP signatures

Cleanups
-----------

* Split test_ffi.cpp into multiple files

Compat Headers
----------------

* OpenSSL compatible API headers: EVP, TLS, certificates, etc

New C APIs
----------------------------------------

* X.509 CRL handling
* PKCS10 requests
* Certificate signing
* Expose TLS
* Expose NIST key wrap with padding
* Expose secret sharing
* Expose deterministic PRNG
* base32
* base58

Python
----------------

* Anywhere Pylint warnings too-many-locals, too-many-branches, or
  too-many-statements are skipped, fix the code so Pylint no longer warns.

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
* Build for Android in CI
* Support hardcoding all test vectors into the botan-test binary
  so it can run as a standalone item (copied to a device, etc)
* Run iOS binary under simulator in CI
* Run the TPM tests against an emulator
  (https://github.com/PeterHuewe/tpm-emulator)
* Add clang-tidy, clang-analyzer, cppcheck to CI
* Add support for vxWorks
* Add support for Fuschia OS
* Add support for CloudABI

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
* Utils for base32 and base58 encoding
* TOTP calculator

Documentation
----------------------------------------

* X.509 certs, path validation
* Specific docs covering one major topic (RSA, ECDSA, AES/GCM, ...)
* Some howto style docs (setting up CA, ...)

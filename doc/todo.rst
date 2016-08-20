Projects
========================================

Feel free to take one of these on if it interests you. Before starting
out on something, send an email to the dev list or open a discussion
ticket on GitHub to make sure you're on the right track.

Request a new feature by opening a pull request to update this file.

Documentation
----------------------------------------

* TPM (no docs)
* PKCS #11 (no docs)
* X.509 certs, path validation
* Specific docs covering one major topic (RSA, ECDSA, AES/GCM, ...)

CLI
----------------------------------------

* Rewrite `tls_client` and `tls_server` to use asio. See `tls_proxy`
  for an example
* `encrypt` / `decrypt` tools providing password and/or public key
  based file encryption
* `bcrypt` cmdlet
* Make help output more helpful
* More microbenchmarks in `speed`: modular exponentiation, ECC point
  multiplication, other BigInt operations
* Compute cycles/byte estimates for benchmark output

TLS
----------------------------------------

* Make DTLS support optional at build time
* Make TLS v1.0 and v1.1 optional at build time
* Curve25519 key exchange
* TLS OCSP stapling (RFC 6066)
* Encrypt-then-MAC extension (RFC 7366)
* Authentication using TOFU (sqlite3 storage)
* Certificate pinning (using TACK?)
* TLS supplemental authorization data (RFC 4680, RFC 5878)
* OpenPGP authentication (RFC 5081)
* DTLS-SCTP (RFC 6083)
* Perspectives (http://perspectives-project.org/)
* Support for server key stored in TPM

PKIX
----------------------------------------

* Support multiple DNS names in certificates
* X.509 policy constraints
* OCSP responder logic
* X.509 attribute certificates (RFC 5755)

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

Accelerators / backends
----------------------------------------

* Extend OpenSSL provider (cipher modes, HMAC)
* /dev/crypto
* Windows CryptoAPI (ciphers, hashes, RSA)
* Apple CommonCrypto
* ARMv8-A crypto extensions (AES, SHA-2)
* POWER8 crypto extensions (AES, SHA-2)
* Better TPM support: NVRAM, PCR measurements, sealing

FFI (Python, OCaml)
----------------------------------------

* Expose certificates
* Expose TLS
* Write a CLI or HTTPS client in Python

Symmetric Algorithms, Hashes, ...
----------------------------------------

* Bitsliced AES or Camellia
* Compressed tables for AES
* AES using vector permutes for NEON, AltiVec
* Use ARMv8 crypto: AES, SHA
* Camellia with AES-NI
* Serpent using AVX2
* Serpent using SSSE3 pshufb for sboxes
* ChaCha20 using SSE2 or AVX2
* scrypt
* Argon2 (draft-irtf-cfrg-argon2)
* bcrypt PBKDF
* Skein-MAC
* ARIA (Korean block cipher, RFCs 5794 and 6209)
* Extend Cascade_Cipher to support arbitrary number of ciphers

Public Key Crypto, Math
----------------------------------------

* XMSS (draft-irtf-cfrg-xmss-hash-based-signatures)
* SPHINCS-256
* NEWHOPE RLWE scheme + BoringSSL compatible TLS cipher suites
* EdDSA (GH #283)
* Ed448-Goldilocks
* FHMQV
* Support mixed hashes and non-empty param strings in OAEP
* Fast new implementations/algorithms for ECC point operations,
  Montgomery multiplication, multi-exponentiation, ...
* Some PK operations, especially RSA, have extensive computations per
  operation setup but many of the computed values depend only on the
  key and could be shared across operation objects.

Library Infrastructure
----------------------------------------

* Add logging callbacks
* Add latency tracing framework

Build
----------------------------------------

* Code signing for Windows installers

Projects
========================================

Request a new feature by opening a pull request to update this file.

Commands
----------------------------------------

* `encrypt` / `decrypt` tools

TLS
----------------------------------------

* Encrypt-then-MAC extension (RFC 7366)
* Authentication using TOFU (sqlite3 storage)
* Certificate pinning (using TACK?)
* TLS OCSP stapling (RFC 6066)
* TLS supplemental authorization data (RFC 4680, RFC 5878)
* OpenPGP authentication (RFC 5081)
* DTLS-SCTP (RFC 6083)
* Perspectives (http://perspectives-project.org/)

PKIX
----------------------------------------

* Support multiple DNS names in certificates
* X.509 name constraints
* X.509 policy constraints
* OCSP responder logic
* X.509 attribute certificates (RFC 5755)

New Protocols
----------------------------------------

* Off-The-Record message protocol
* Some useful subset of OpenPGP
* SSHv2 client and/or server
* Cash schemes (such as Lucre, credlib, bitcoin?)

  Accelerators / backends
----------------------------------------

* Extend OpenSSL provider (cipher modes, HMAC)
* /dev/crypto
* Windows CryptoAPI
* Apple CommonCrypto
* ARMv8 crypto extensions
* Intel Skylake SHA-1/SHA-2

FFI (Python, OCaml)
----------------------------------------

* Expose certificates
* Expose TLS

Symmetric Algorithms, Hashes, ...
----------------------------------------

* Bitsliced AES or Camellia
* Compressed tables for AES
* Camellia with AES-NI
* Serpent using AVX2
* Serpent using SSSE3 pshufb for sboxes
* ChaCha20 using SSE2 or AVX2
* scrypt
* bcrypt PBKDF
* BLAKE2b
* Skein-MAC
* ARIA (Korean block cipher, RFCs 5794 and 6209)
* Extend Cascade_Cipher to support arbitrary number of ciphers

Public Key Crypto, Math
----------------------------------------

* EdDSA (GH #283)
* Ed448-Goldilocks
* FHMQV
* Support mixed hashes and non-empty param strings in OAEP
* Fast new implementations/algorithms for ECC point operations,
  Montgomery multiplication, multi-exponentiation, ...
* Some PK operations, especially RSA, have extensive computations per
  operation setup but many of the computed values depend only on the
  key and could be shared across operation objects.
* Have BigInt '%' and '/' operators compute and cache the Barrett
  reduction value on the BigInt.

Library Infrastructure
----------------------------------------
* Add logging callbacks
* Add latency tracing framework
* Compute cycles/byte estimates for benchmark output

Build
----------------------------------------

* Code signing for Windows installers

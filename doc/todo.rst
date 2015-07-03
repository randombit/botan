Todos
========================================

These are features either requested by users or that seem like
potentially useful things to have. Several are quite self-contained
and could make a quick project.

Request a new feature by opening a pull request to update this file.

Symmetric Algorithms, Hashes, ...
----------------------------------------

* Bitsliced AES or Camellia
* Camellia with AES-NI
* Serpent using AVX2
* scrypt
* BLAKE2b
* Skein-MAC
* ARIA (Korean block cipher, RFCs 5794 and 6209)
* Extend Cascade_Cipher to support arbitrary number of ciphers

Public Key Crypto, Math
----------------------------------------

* EdDSA
* Ed448-Goldilocks
* Fast new implementations/algorithms for ECC point operations,
  Montgomery multiplication, multi-exponentiation, ...

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

* Improve OpenSSL provider (add cipher modes, RSA, etc)
* /dev/crypto
* Windows CryptoAPI
* Apple CommonCrypto
* ARMv8 crypto extensions
* Intel Skylake SHA-1/SHA-2

FFI (Python, OCaml)
----------------------------------------

* Expose TLS

Build
----------------------------------------

* Code signing for Windows installers

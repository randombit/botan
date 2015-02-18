Todos
========================================

These are features either requested by users or that seem like
potentially useful things to have. Several are quite self-contained
and could make a quick project.

Request a new feature by sending a patch.

Basic Crypto
----------------------------------------

* scrypt
* BLAKE2
* EdDSA
* Skein-MAC
* ARIA (Korean block cipher, RFCs 5794 and 6209)
* Extend Cascade_Cipher to support arbitrary number of ciphers

TLS
----------------------------------------

* Encrypt-then-MAC extension (RFC 7366)
* Authentication using TOFU (sqlite3 storage)
* Certificate pinning (using TACK?)
* TLS OCSP stapling (RFC 6066)
* ALPN (RFC 7301)
* TLS supplemental authorization data (RFC 4680, RFC 5878)
* OpenPGP authentication (RFC 5081)
* DTLS-SCTP (RFC 6083)
* Perspectives (http://perspectives-project.org/)

PKIX
----------------------------------------

* OCSP responder logic
* X.509 attribute certificates (RFC 5755)

ECC / BigInt / Math
----------------------------------------

* Specialized reductions for P-256 and P-384
* MP asm optimizations - SSE2, ARM/NEON, ...

New Protocols
----------------------------------------

* Off-The-Record message protocol
* Some useful subset of OpenPGP
* SSHv2 server
* Cash schemes (such as Lucre, credlib, bitcoin?)

Accelerators / backends
----------------------------------------

* Improve OpenSSL provider (add cipher modes, RSA, etc)
* /dev/crypto
* Windows CryptoAPI
* Apple CommonCrypto
* ARMv8 crypto extensions
* Intel Skylake SHA-1/SHA-2

Python
----------------------------------------

* TLS, ECDSA, bcrypt, ...

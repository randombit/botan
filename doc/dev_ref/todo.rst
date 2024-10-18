Todo List
========================================

Feel free to take one of these on if it interests you. Before starting
out on something, send an email to the dev list or open a discussion
ticket on GitHub to make sure you're on the right track.

Request a new feature by opening a pull request to update this file.

New Ciphers/Hashes/MACs
----------------------------------------
* GCM-SIV (RFC 8452)
* EME* tweakable block cipher (https://eprint.iacr.org/2004/125)
* PMAC
* SIV-PMAC
* Threefish-1024
* Skein-MAC
* FFX format preserving encryption (NIST 800-38G)
* Adiantum (https://eprint.iacr.org/2018/720)
* HPKE (RFC 9180)
* Blake3

Hardware Specific Optimizations
----------------------------------------

* Stiched AES/GCM mode for CPUs supporting both AES and CLMUL
* Combine AES-NI, ARMv8 and POWER AES implementations (as already done for CLMUL)
* GFNI implementations for: Camellia, SEED, ARIA
* NEON/VMX support for the SIMD based GHASH
* Vector permute AES only supports little-endian systems; fix for big-endian
* Poly1305 using AVX2
* SHA-512 using BMI2+AVX2 and/or new Intel instructions
* SM3 using x86 SM3-NI
* SM4 using x86 SM4-NI
* Constant time bitsliced DES
* SIMD evaluation of SHA-2 and SHA-3 compression functions
* Improved Salsa implementations (SIMD_4x32 and/or AVX2)
* Add CLMUL/PMULL implementations for CRC24/CRC32
* Add support for ARMv8.4-A SHA-3, SM3 and RNG instructions
* POWER8 SHA-2 extensions (GH #1486 + #1487)
* Add support for VPSUM on big-endian PPC64 (GH #2252)
* Add support for RISC-V crypto extensions

Public Key Crypto, Math
----------------------------------------

* Short vector optimization for BigInt
* BLS12-381 pairing, BLS signatures
* Identity based encryption
* Paillier homomorphic cryptosystem
* New PAKEs (pending CFRG bakeoff results)
* SPHINX password store (https://eprint.iacr.org/2018/695)

Utility Functions
------------------

* Constant time base64 and hex is optimized using SWAR; apply this to base32 and base58
* Make Memory_Pool more concurrent (currently uses a global lock)
* Guarded integer type to prevent overflow bugs

External Providers
----------------------------------------

* /dev/crypto provider (ciphers, hashes)
* Windows CryptoNG provider (ciphers, hashes)
* Extend Apple CommonCrypto provider (HMAC, CMAC, RSA, ECDSA, ECDH)
* Add support for iOS keychain access
* Extend support for TPM 2.0 (PCR, NVRAM, Policies, etc)

TLS
----------------------------------------

* Make DTLS support optional at build time
* Make TLS 1.2 support optional at build time
* Improve/optimize DTLS defragmentation and retransmission
* Make RSA optional at build time
* Make finite field DH optional at build time
* Certificate Transparency extensions
* TLS supplemental authorization data (RFC 4680, RFC 5878)
* DTLS-SCTP (RFC 6083)

PKIX
----------------------------------------

* Further tests of validation API (see GH #785)
* Test suite for validation of 'real world' cert chains (GH #611)
* X.509 policy constraints
* OCSP responder logic

New Protocols / Formats
----------------------------------------

* Noise protocol
* ACME protocol (needs a story for JSON)
* Cryptographic Message Syntax (RFC 5652)
* Fernet symmetric encryption (https://cryptography.io/en/latest/fernet/)
* RNCryptor format (https://github.com/RNCryptor/RNCryptor)
* Age format (https://age-encryption.org/v1)
* Useful OpenPGP subset 1: symmetrically encrypted files.
  Not aiming to process arbitrary OpenPGP, but rather produce
  something that happens to be readable by `gpg` and is relatively
  simple to process for decryption. Require AEAD mode (EAX/OCB).
* Useful OpenPGP subset 2: Process OpenPGP public keys
* Useful OpenPGP subset 3: Verification of OpenPGP signatures

Cleanups
-----------

* Unicode path support on Windows (GH #1615)
* The X.509 path validation tests have much duplicated logic

New C APIs
----------------------------------------

* PKCS10 requests
* Certificate signing
* CRLs
* Expose TLS
* Expose secret sharing
* Expose deterministic PRNG
* base32
* base58
* DL_Group
* EC_Group

Build/Test
----------------------------------------

* Support hardcoding all test vectors into the botan-test binary
  so it can run as a standalone item (copied to a device, etc)
* Run iOS binary under simulator in CI
* Run Android binary under simulator in CI
* Add support for vxWorks

CLI
----------------------------------------

* Add a ``--completion`` option to dump autocomplete info, write
  support for autocompletion in bash/zsh.
* Change `tls_server` to be a tty<->socket app, like `tls_client` is,
  instead of a bogus echo server.
* `encrypt` / `decrypt` tools providing password based file encryption
* Add ECM factoring
* Clone of `minisign` signature utility
* Password store utility
* TOTP calculator
* Clone of magic wormhole
* ACVP client (https://github.com/usnistgov/ACVP)

Documentation
----------------------------------------

* Always needs help

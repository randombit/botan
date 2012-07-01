
.. _algo_list:

Algorithms
========================================

Supported Algorithms
----------------------------------------

Botan provides a number of different cryptographic algorithms and
primitives, including:

* Public key cryptography

  * Encryption algorithms RSA, ElGamal, DLIES (padding schemes OAEP,
    PKCS #1 v1.5)
  * Signature algorithms RSA, DSA, ECDSA, GOST 34.10-2001,
    Nyberg-Rueppel, Rabin-Williams (padding schemes PSS, PKCS #1 v1.5,
    X9.31)
  * Key agreement techniques Diffie-Hellman and ECDH

* Hash functions

  * NIST hashes: SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512
  * RIPE hashes: RIPEMD-160 and RIPEMD-128
  * SHA-3 candidates Skein-512, Keccak, and Blue Midnight Wish-512
  * Other common hash functions Whirlpool and Tiger
  * National standard hashes HAS-160 and GOST 34.11
  * Obsolete or insecure hashes MD5, MD4, MD2
  * Non-cryptographic checksums Adler32, CRC24, CRC32

* Block ciphers

  * AES (Rijndael) and AES candidates Serpent, Twofish, MARS, CAST-256, RC6
  * DES, and variants 3DES and DESX
  * National/telecom block ciphers SEED, KASUMI, MISTY1, GOST 28147, Skipjack
  * Other block ciphers including Blowfish, CAST-128, IDEA, Noekeon,
    TEA, XTEA, RC2, RC5, SAFER-SK, and Square
  * Block cipher constructions Luby-Rackoff and Lion
  * Block cipher modes ECB, CBC, CBC/CTS, CFB, OFB, CTR, XTS and
    authenticated cipher mode EAX

* Stream ciphers ARC4, Salsa20/XSalsa20, Turing, and WiderWake4+1

* Authentication codes HMAC, CMAC (aka OMAC1), CBC-MAC, ANSI X9.19
  DES-MAC, and the protocol-specific SSLv3 authentication code

* Public Key Infrastructure

  * X.509 certificates (including generating new self-signed and CA
    certs) and CRLs
  * Certificate path validation
  * PKCS #10 certificate requests (creation and certificate issue)

* Other cryptographic utility functions including

  * Key derivation functions for passwords: PBKDF1 (PKCS #5 v1.5),
    PBKDF2 (PKCS #5 v2.0), OpenPGP S2K (RFC 2440)
  * General key derivation functions KDF1 and KDF2 from IEEE 1363
  * PRFs from ANSI X9.42, SSL v3.0, TLS v1.0

Recommended Algorithms
---------------------------------

This section is by no means the last word on selecting which
algorithms to use.  However, botan includes a sometimes bewildering
array of possible algorithms, and unless you're familiar with the
latest developments in the field, it can be hard to know what is
secure and what is not. The following attributes of the algorithms
were evaluated when making this list: security, standardization,
patent status, support by other implementations, and efficiency (in
roughly that order).

It is intended as a set of simple guidelines for developers, and
nothing more.  It's entirely possible that there are algorithms that
will turn out to be more secure than the ones listed, but the
algorithms listed here are (currently) thought to be safe.

* Block ciphers: AES or Serpent in CBC, CTR, or XTS mode

* Hash functions: SHA-256, SHA-512

* MACs: HMAC with any recommended hash function

* Public Key Encryption: RSA with "EME1(SHA-256)"

* Public Key Signatures: RSA with EMSA4 and any recommended hash, or
  DSA or ECDSA with "EMSA1(SHA-256)"

* Key Agreement: Diffie-Hellman or ECDH, with "KDF2(SHA-256)"

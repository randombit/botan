
.. _algo_list:

Algorithms
========================================

Supported Algorithms
----------------------------------------

Botan provides a number of different cryptographic algorithms and
primitives, including:

TLS/Public Key Infrastructure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  * SSL/TLS (from SSL v3 to TLS v1.2), including using preshared
    keys (TLS-PSK) or passwords (TLS-SRP)
  * X.509 certificates (including generating new self-signed and CA
    certs) and CRLs
  * Certificate path validation
  * PKCS #10 certificate requests (creation and certificate issue)

Public Key Cryptography
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  * Encryption algorithms RSA, ElGamal, DLIES (padding schemes OAEP,
    PKCS #1 v1.5)
  * Signature algorithms RSA, DSA, ECDSA, GOST 34.10-2001,
    Nyberg-Rueppel, Rabin-Williams (padding schemes PSS, PKCS #1 v1.5,
    X9.31)
  * Key agreement techniques Diffie-Hellman and ECDH

Hash functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  * NIST hashes: SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512
  * SHA-3 (Keccak) and SHA-3 candidates Skein-512 and Blue Midnight Wish-512
  * RIPE hashes: RIPEMD-160 and RIPEMD-128
  * Hash function combiners (Parallel and Comb4P)
  * Other common hash functions Whirlpool and Tiger
  * National standard hashes HAS-160 and GOST 34.11
  * Obsolete or insecure hashes MD5, MD4, MD2
  * Non-cryptographic checksums Adler32, CRC24, CRC32

Block ciphers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  * Authenticated cipher modes EAX, OCB, and GCM
  * Unauthenticated cipher modes CTR, CBC, XTS, CFB, OFB, and ECB
  * AES (Rijndael) and AES candidates Serpent, Twofish, MARS, CAST-256, RC6
  * DES, and variants 3DES and DESX
  * National/telecom block ciphers SEED, KASUMI, MISTY1, GOST 28147
  * Other block ciphers including Blowfish, CAST-128, IDEA, Noekeon,
    Skipjack, TEA, XTEA, RC2, RC5, SAFER-SK, and Square
  * Block cipher constructions Luby-Rackoff and Lion

Stream Ciphers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 * RC4
 * Salsa20/XSalsa20
 * CTR and OFB modes also present a stream cipher interface

Authentication Codes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 * HMAC, CMAC (aka OMAC1)
 * Obsolete designs CBC-MAC, ANSI X9.19 DES-MAC, and the
   protocol-specific SSLv3 authentication code

Other Useful Things
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  * Key derivation functions for passwords, including PBKDF2
  * Password hashing functions, including bcrypt
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

If your data is in motion, strongly consider using :doc:`tls` as a
pre built, already standard and well studied protocol.

Otherwise, if you simply *must* do something custom, use:

* Block ciphers: AES or Serpent in EAX mode, or in CBC, CTR, or XTS
  mode with a message authentication code.

* General hash functions: SHA-256, SHA-512, SHA-3

* Message authentication: HMAC with SHA-256

* Public Key Encryption: RSA, 2048+ bit keys, with OAEP and SHA-256
  ("EME1(SHA-256)")

* Public Key Signatures: RSA, 2048+ bit keys with PSS and SHA-512
  ("EMSA4(SHA-512)")

* Key Agreement: Diffie-Hellman or ECDH, with "KDF2(SHA-256)"

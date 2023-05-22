
Cryptobox
========================================

Encryption using a passphrase
----------------------------------------

.. versionadded:: 1.8.6

.. deprecated:: 3.0

This is a set of simple routines that encrypt some data using a
passphrase. There are defined in the header `cryptobox.h`, inside
namespace `Botan::CryptoBox`.

It generates cipher and MAC keys using 8192 iterations of PBKDF2 with
HMAC(SHA-512), then encrypts using Serpent in CTR mode and authenticates using a
HMAC(SHA-512) mac of the ciphertext, truncated to 160 bits.

.. doxygennamespace:: Botan::CryptoBox
   :content-only:


Cryptobox
========================================

Encryption using a passphrase
----------------------------------------

.. versionadded:: 1.8.6

This is a set of simple routines that encrypt some data using a
passphrase. There are defined in the header `cryptobox.h`, inside
namespace `Botan::CryptoBox`.

It generates cipher and MAC keys using 8192 iterations of PBKDF2 with
HMAC(SHA-512), then encrypts using Serpent in CTR mode and authenticates using a
HMAC(SHA-512) mac of the ciphertext, truncated to 160 bits.

 .. cpp:function:: std::string encrypt(const uint8_t input[], size_t input_len, \
                                       const std::string& passphrase, \
                                       RandomNumberGenerator& rng)

    Encrypt the contents using *passphrase*.

 .. cpp:function:: std::string decrypt(const uint8_t input[], size_t input_len, \
                                       const std::string& passphrase)

    Decrypts something encrypted with encrypt.

 .. cpp:function:: std::string decrypt(const std::string& input, \
                                       const std::string& passphrase)

    Decrypts something encrypted with encrypt.


Cryptobox
==================================================

This is a set of simple routines that cover some common cases. They
are defined in the header `cryptobox.h`, inside namespace
`Botan::CryptoBox`.

 .. cpp:function:: std::string encrypt(const byte input[], size_t input_len, \
                                       const std::string& passphrase, \
                                       RandomNumberGenerator& rng)

    Encrypt the contents using *passphrase*.

 .. cpp:function:: std::string decrypt(const byte input[], size_t input_len, \
                                       const std::string& passphrase)

    Decrypts something encrypted with encrypt.

 .. cpp:function:: std::string decrypt(const std::string& input,
                                       const std::string& passphrase)

    Decrypts something encrypted with encrypt.


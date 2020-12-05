Block Ciphers
=======================

Block ciphers are a n-bit permutation for some small n, typically 64 or 128
bits.  They are a cryptographic primitive used to generate higher level
operations such as authenticated encryption.

.. warning::

   In almost all cases, a bare block cipher is not what you should be using.
   You probably want an authenticated cipher mode instead (see :ref:`cipher_modes`)
   This interface is used to build higher level operations (such as cipher
   modes or MACs), or in the very rare situation where ECB is required,
   eg for compatibility with an existing system.

.. cpp:class:: BlockCipher

  .. cpp:function:: static std::unique_ptr<BlockCipher> create(const std::string& algo_spec, \
                                                               const std::string& provider = "")

      Create a new block cipher object, or else return null.

  .. cpp:function:: static std::unique_ptr<BlockCipher> create_or_throw(const std::string& algo_spec, \
                                                                        const std::string& provider = "")

      Like ``create``, except instead of returning null an exception is thrown
      if the cipher is not known.

  .. cpp:function:: void set_key(const uint8_t* key, size_t length)

      This sets the key to the value specified. Most algorithms only accept keys
      of certain lengths. If you attempt to call ``set_key`` with a key length
      that is not supported, the exception ``Invalid_Key_Length`` will be
      thrown.

      In all cases, ``set_key`` must be called on an object before any data
      processing (encryption, decryption, etc) is done by that object. If this
      is not done, an exception will be thrown.
      thrown.

  .. cpp:function:: bool valid_keylength(size_t length) const

     This function returns true if and only if *length* is a valid keylength for
     this algorithm.

  .. cpp:function:: size_t minimum_keylength() const

     Return the smallest key length (in bytes) that is acceptable for the
     algorithm.

  .. cpp:function:: size_t maximum_keylength() const

     Return the largest key length (in bytes) that is acceptable for the
     algorithm.

  .. cpp:function:: std::string name() const

      Return a human readable name for this algorithm. This is guaranteed to round-trip with
      ``create`` and ``create_or_throw`` calls, ie create("Foo")->name() == "Foo"

  .. cpp:function:: void clear()

     Zero out the key. The key must be reset before the cipher object can be used.

  .. cpp:function:: BlockCipher* clone() const

     Return a newly allocated BlockCipher object of the same type as this one.

  .. cpp:function:: size_t block_size() const

      Return the size (in *bytes*) of the cipher.

  .. cpp:function:: size_t parallelism() const

     Return the parallelism underlying this implementation of the cipher. This
     value can vary across versions and machines. A return value of N means that
     encrypting or decrypting with N blocks can operate in parallel.

  .. cpp:function:: size_t parallel_bytes() const

     Returns ``parallelism`` multiplied by the block size as well as a small
     fudge factor. That's because even ciphers that have no implicit parallelism
     typically see a small speedup for being called with several blocks due to
     caching effects.

  .. cpp:function:: std::string provider() const

     Return the provider type. Default value is "base" but can be any arbitrary string.
     Other example values are "sse2", "avx2", "openssl".

  .. cpp:function:: void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const

     Encrypt *blocks* blocks of data, taking the input from the array *in* and
     placing the ciphertext into *out*. The two pointers may be identical, but
     should not overlap ranges.

  .. cpp:function:: void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const

     Decrypt *blocks* blocks of data, taking the input from the array *in* and
     placing the plaintext into *out*. The two pointers may be identical, but
     should not overlap ranges.

  .. cpp:function:: void encrypt(const uint8_t in[], uint8_t out[]) const

     Encrypt a single block. Equivalent to :cpp:func:`encrypt_n`\ (in, out, 1).

  .. cpp:function:: void encrypt(uint8_t block[]) const

     Encrypt a single block. Equivalent to :cpp:func:`encrypt_n`\ (block, block, 1)

  .. cpp:function:: void decrypt(const uint8_t in[], uint8_t out[]) const

     Decrypt a single block. Equivalent to :cpp:func:`decrypt_n`\ (in, out, 1)

  .. cpp:function:: void decrypt(uint8_t block[]) const

     Decrypt a single block. Equivalent to :cpp:func:`decrypt_n`\ (block, block, 1)

  .. cpp:function:: template<typename Alloc> void encrypt(std::vector<uint8_t, Alloc>& block) const

     Assumes ``block`` is of a multiple of the block size.

  .. cpp:function:: template<typename Alloc> void decrypt(std::vector<uint8_t, Alloc>& block) const

     Assumes ``block`` is of a multiple of the block size.

Code Example
-----------------

For sheer demonstrative purposes, the following code encrypts a provided single
block of plaintext with AES-256 using two different keys.

.. code-block:: cpp

    #include <botan/block_cipher.h>
    #include <botan/hex.h>
    #include <iostream>
    int main ()
       {
       std::vector<uint8_t> key = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
       std::vector<uint8_t> block = Botan::hex_decode("00112233445566778899AABBCCDDEEFF");
       std::unique_ptr<Botan::BlockCipher> cipher(Botan::BlockCipher::create("AES-256"));
       cipher->set_key(key);
       cipher->encrypt(block);
       std::cout << std::endl <<cipher->name() << "single block encrypt: " << Botan::hex_encode(block);

       //clear cipher for 2nd encryption with other key
       cipher->clear();
       key = Botan::hex_decode("1337133713371337133713371337133713371337133713371337133713371337");
       cipher->set_key(key);
       cipher->encrypt(block);

       std::cout << std::endl << cipher->name() << "single block encrypt: " << Botan::hex_encode(block);
       return 0;
       }

Available Ciphers
---------------------

Botan includes a number of block ciphers that are specific to particular countries, as
well as a few that are included mostly due to their use in specific protocols such as PGP
but not widely used elsewhere. If you are developing new code and have no particular
opinion, use AES-256. If you desire an alternative to AES, consider Serpent, SHACAL2 or
Threefish.

.. warning:: Avoid any 64-bit block cipher in new designs. There are
             combinatoric issues that affect any 64-bit cipher that render it
             insecure when large amounts of data are processed.

AES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Comes in three variants, AES-128, AES-192, and AES-256.

The standard 128-bit block cipher. Many modern platforms offer hardware
acceleration. However, on platforms without hardware support, AES
implementations typically are vulnerable to side channel attacks. For x86
systems with SSSE3 but without AES-NI, Botan has an implementation which avoids
known side channels.

Available if ``BOTAN_HAS_AES`` is defined.

ARIA
~~~~~~

South Korean cipher used in industry there. No reason to use it otherwise.

Available if ``BOTAN_HAS_ARIA`` is defined.

Blowfish
~~~~~~~~~

A 64-bit cipher popular in the pre-AES era. Very slow key setup. Also used (with
bcrypt) for password hashing.

Available if ``BOTAN_HAS_BLOWFISH`` is defined.

CAST-128
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 64-bit cipher, commonly used in OpenPGP.

Available if ``BOTAN_HAS_CAST128`` is defined.

CAST-256
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 128-bit cipher that was a contestant in the NIST AES competition.
Almost never used in practice. Prefer AES or Serpent.

Available if ``BOTAN_HAS_CAST256`` is defined.

.. warning::
   Support for CAST-256 is deprecated and will be removed in a future major release.

Camellia
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Comes in three variants, Camellia-128, Camellia-192, and Camellia-256.

A Japanese design standardized by ISO, NESSIE and CRYPTREC.
Rarely used outside of Japan.

Available if ``BOTAN_HAS_CAMELLIA`` is defined.

Cascade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Creates a block cipher cascade, where each block is encrypted by two ciphers
with independent keys. Useful if you're very paranoid. In practice any single
good cipher (such as Serpent, SHACAL2, or AES-256) is more than sufficient.

Available if ``BOTAN_HAS_CASCADE`` is defined.

DES, 3DES, DESX
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Originally designed by IBM and NSA in the 1970s. Today, DES's 56-bit key renders
it insecure to any well-resourced attacker. DESX and 3DES extend the key length,
and are still thought to be secure, modulo the limitation of a 64-bit block.
All are somewhat common in some industries such as finance. Avoid in new code.

.. warning::
   Support for DESX is deprecated and it will be removed in a future major release.

Available if ``BOTAN_HAS_DES`` is defined.

GOST-28147-89
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Aka "Magma". An old 64-bit Russian cipher. Possible security issues, avoid
unless compatibility is needed.

Available if ``BOTAN_HAS_GOST_28147_89`` is defined.

.. warning::
   Support for this cipher is deprecated and will be removed in a future major release.

IDEA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An older but still unbroken 64-bit cipher with a 128-bit key. Somewhat common
due to its use in PGP. Avoid in new designs.

Available if ``BOTAN_HAS_IDEA`` is defined.

Kasumi
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 64-bit cipher used in 3GPP mobile phone protocols. There is no reason to use
it outside of this context.

Available if ``BOTAN_HAS_KASUMI`` is defined.

.. warning::
   Support for Kasumi is deprecated and will be removed in a future major release.

Lion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A "block cipher construction" which can encrypt blocks of nearly arbitrary
length.  Built from a stream cipher and a hash function. Useful in certain
protocols where being able to encrypt large or arbitrary length blocks is
necessary.

Available if ``BOTAN_HAS_LION`` is defined.

MISTY1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 64-bit Japanese cipher standardized by NESSIE and ISO. Seemingly secure, but
quite slow and saw little adoption. No reason to use it in new code.

Available if ``BOTAN_HAS_MISTY1`` is defined.

.. warning::
   Support for MISTY1 is deprecated and will be removed in a future major release.

Noekeon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A fast 128-bit cipher by the designers of AES. Easily secured against side
channels.

Available if ``BOTAN_HAS_NOEKEON`` is defined.

.. warning::
   Support for Noekeon is deprecated and will be removed in a future major release.

SEED
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A older South Korean cipher, widely used in industry there. No reason to choose it otherwise.

Available if ``BOTAN_HAS_SEED`` is defined.

SHACAL2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The 256-bit block cipher used inside SHA-256. Accepts up to a 512-bit key.
Fast, especially when SIMD or SHA-2 acceleration instructions are available.
Standardized by NESSIE but otherwise obscure.

Available if ``BOTAN_HAS_SHACAL2`` is defined.

SM4
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 128-bit Chinese national cipher, required for use in certain commercial
applications in China. Quite slow. Probably no reason to use it outside of legal
requirements.

Available if ``BOTAN_HAS_SM4`` is defined.

Serpent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An AES contender. Widely considered the most conservative design. Fairly slow
unless SIMD instructions are available.

Available if ``BOTAN_HAS_SERPENT`` is defined.

Threefish-512
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 512-bit tweakable block cipher that was used in the Skein hash function.
Very fast on 64-bit processors.

Available if ``BOTAN_HAS_THREEFISH_512`` is defined.

Twofish
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 128-bit block cipher that was one of the AES finalists. Has a somewhat complicated key
setup and a "kitchen sink" design.

Available if ``BOTAN_HAS_TWOFISH`` is defined.

XTEA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 64-bit cipher popular for its simple implementation. Avoid in new code.

Available if ``BOTAN_HAS_XTEA`` is defined.

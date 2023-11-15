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

  .. cpp:function:: std::unique_ptr<BlockCipher> new_object() const

     Return a newly allocated BlockCipher object of the same type as this one.
     The new object is unkeyed.

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

.. _block_cipher_example:

Code Example
-----------------

For sheer demonstrative purposes, the following code encrypts a provided single
block of plaintext with AES-256 using two different keys.

.. literalinclude:: /../src/examples/aes.cpp
   :language: cpp

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

Algorithm specification names:

- ``AES-128``
- ``AES-192``
- ``AES-256``

ARIA
~~~~~~

South Korean cipher used in industry there. No reason to use it otherwise.

Available if ``BOTAN_HAS_ARIA`` is defined.

Algorithm specification names:

- ``ARIA-128``
- ``ARIA-192``
- ``ARIA-256``

Blowfish
~~~~~~~~~

A 64-bit cipher popular in the pre-AES era. Very slow key setup. Also used (with
bcrypt) for password hashing.

Available if ``BOTAN_HAS_BLOWFISH`` is defined.

Algorithm specification name: ``Blowfish``

Camellia
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Comes in three variants, Camellia-128, Camellia-192, and Camellia-256.

A Japanese design standardized by ISO, NESSIE and CRYPTREC.
Rarely used outside of Japan.

Available if ``BOTAN_HAS_CAMELLIA`` is defined.

Algorithm specification names:

- ``Camellia-128``
- ``Camellia-192``
- ``Camellia-256``

Cascade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Creates a block cipher cascade, where each block is encrypted by two ciphers
with independent keys. Useful if you're very paranoid. In practice any single
good cipher (such as Serpent, SHACAL2, or AES-256) is more than sufficient.

Available if ``BOTAN_HAS_CASCADE`` is defined.

Algorithm specification name:
``Cascade(<BlockCipher 1>,<BlockCipher 2>)``, e.g. ``Cascade(Serpent,AES-256)``

CAST-128
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 64-bit cipher, commonly used in OpenPGP.

Available if ``BOTAN_HAS_CAST128`` is defined.

Algorithm specification name:

- ``CAST-128`` (reported name) / ``CAST5``

DES and 3DES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Originally designed by IBM and NSA in the 1970s. Today, DES's 56-bit key renders
it insecure to any well-resourced attacker. 3DES extends the key length,
and is still thought to be secure, modulo the limitation of a 64-bit block.
All are somewhat common in some industries such as finance. Avoid in new code.

Available if ``BOTAN_HAS_DES`` is defined.

Algorithm specification names:

- ``DES``
- ``TripleDES`` (reported name) / ``3DES`` / ``DES-EDE``

GOST-28147-89
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Aka "Magma". An old 64-bit Russian cipher. Possible security issues, avoid
unless compatibility is needed.

Available if ``BOTAN_HAS_GOST_28147_89`` is defined.

.. warning::
   Support for this cipher is deprecated and will be removed in a future major release.

Algorithm specification names:

- ``GOST-28147-89`` / ``GOST-28147-89(R3411_94_TestParam)`` (reported name)
- ``GOST-28147-89(R3411_CryptoPro)``

IDEA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An older but still unbroken 64-bit cipher with a 128-bit key. Somewhat common
due to its use in PGP. Avoid in new designs.

Available if ``BOTAN_HAS_IDEA`` is defined.

Algorithm specification name: ``IDEA``

Kuznyechik
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: 3.2

Newer Russian national cipher, also known as GOST R 34.12-2015 or "Grasshopper".

.. warning::

   The sbox of this cipher is supposedly random, but was found to have a
   mathematical structure which is exceedingly unlikely to have occured by
   chance. This may indicate the existence of a backdoor or other issue. Avoid
   using this cipher unless strictly required.

Available if ``BOTAN_HAS_KUZNYECHIK`` is defined.

Algorithm specification name: ``Kuznyechik``

Lion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A "block cipher construction" which can encrypt blocks of nearly arbitrary
length.  Built from a stream cipher and a hash function. Useful in certain
protocols where being able to encrypt large or arbitrary length blocks is
necessary.

Available if ``BOTAN_HAS_LION`` is defined.

Algorithm specification name:
``Lion(<HashFunction>,<StreamCipher>,<optional block size>)``

- Block size defaults to 1024.
- Examples: ``Lion(SHA-1,RC4,64)``

Noekeon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A fast 128-bit cipher by the designers of AES. Easily secured against side
channels. Quite obscure however.

Available if ``BOTAN_HAS_NOEKEON`` is defined.

.. warning::
   Noekeon support is deprecated and will be removed in a future major release.

Algorithm specification name: ``Noekeon``

SEED
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A older South Korean cipher, widely used in industry there. No reason to choose it otherwise.

Available if ``BOTAN_HAS_SEED`` is defined.

Algorithm specification name: ``SEED``

Serpent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An AES contender. Widely considered the most conservative design. Fairly slow
unless SIMD instructions are available.

Available if ``BOTAN_HAS_SERPENT`` is defined.

Algorithm specification name: ``Serpent``

SHACAL2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The 256-bit block cipher used inside SHA-256. Accepts up to a 512-bit key.
Fast, especially when SIMD or SHA-2 acceleration instructions are available.
Standardized by NESSIE but otherwise obscure.

Available if ``BOTAN_HAS_SHACAL2`` is defined.

Algorithm specification name: ``SHACAL2``

SM4
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 128-bit Chinese national cipher, required for use in certain commercial
applications in China. Quite slow. Probably no reason to use it outside of legal
requirements.

Available if ``BOTAN_HAS_SM4`` is defined.

Algorithm specification name: ``SM4``

Threefish-512
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 512-bit tweakable block cipher that was used in the Skein hash function.
Very fast on 64-bit processors.

Available if ``BOTAN_HAS_THREEFISH_512`` is defined.

Algorithm specification name: ``Threefish-512``

Twofish
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A 128-bit block cipher that was one of the AES finalists. Has a somewhat complicated key
setup and a "kitchen sink" design.

Available if ``BOTAN_HAS_TWOFISH`` is defined.

Algorithm specification name: ``Twofish``

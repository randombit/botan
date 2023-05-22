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

Code Example
-----------------

For sheer demonstrative purposes, the following code encrypts a provided single
block of plaintext with AES-256 using two different keys.

.. literalinclude:: /../src/examples/aes.cpp
   :language: cpp

API Overview
------------

.. container:: toggle

   .. doxygenclass:: Botan::BlockCipher
      :members: create,create_or_throw,set_key,minimum_keylength,maximum_keylength,encrypt,decrypt,encrypt_n,decrypt_n

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

DES and 3DES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Originally designed by IBM and NSA in the 1970s. Today, DES's 56-bit key renders
it insecure to any well-resourced attacker. 3DES extends the key length,
and is still thought to be secure, modulo the limitation of a 64-bit block.
All are somewhat common in some industries such as finance. Avoid in new code.

Most implementations of DES, including the one currently used in Botan, are
vulnerable to side channel attacks - another reason to avoid it.

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

Lion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A "block cipher construction" which can encrypt blocks of nearly arbitrary
length.  Built from a stream cipher and a hash function. Useful in certain
protocols where being able to encrypt large or arbitrary length blocks is
necessary.

Available if ``BOTAN_HAS_LION`` is defined.

Noekeon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A fast 128-bit cipher by the designers of AES. Easily secured against side
channels. Quite obscure however.

Available if ``BOTAN_HAS_NOEKEON`` is defined.

.. warning::
   Noekeon support is deprecated and will be removed in a future major release.

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

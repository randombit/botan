
Format Preserving Encryption
========================================

.. versionadded:: 1.9.17

Format preserving encryption (FPE) refers to a set of techniques for
encrypting data such that the ciphertext has the same format as the
plaintext. For instance, you can use FPE to encrypt credit card
numbers with valid checksums such that the ciphertext is also an
credit card number with a valid checksum, or similiarly for bank
account numbers, US Social Security numbers, or even more general
mappings like English words onto other English words.

The scheme currently implemented in botan is called FE1, and described
in the paper `Format Preserving Encryption
<http://eprint.iacr.org/2009/251>`_ by Mihir Bellare, Thomas
Ristenpart, Phillip Rogaway, and Till Stegers. FPE is an area of
ongoing standardization and it is likely that other schemes will be
included in the future.

To use FE1, use these functions, from ``fpe_fe1.h``:

.. cpp:function:: BigInt FPE::fe1_encrypt(const BigInt& n, const BigInt& X, \
   const SymmetricKey& key, const MemoryRegion<byte>& tweak)

   Encrypts the value *X* modulo the value *n* using the *key* and
   *tweak* specified. Returns an integer less than *n*. The *tweak* is
   a value that does not need to be secret that parameterizes the
   encryption function. For instance, if you were encrypting a
   database column with a single key, you could use a per-row-unique
   integer index value as the tweak.

   To encrypt an arbitrary value using FE1, you need to use a ranking
   method. Basically, the idea is to assign an integer to every value
   you might encrypt. For instance, a 16 digit credit card number
   consists of a 15 digit code plus a 1 digit checksum. So to encrypt
   a credit card number, you first remove the checksum, encrypt the 15
   digit value modulo 10\ :sup:`15`, and then calculate what the
   checksum is for the new (ciphertext) number.

.. cpp:function:: BigInt FPE::fe1_decrypt(const BigInt& n, const BigInt& X, \
   const SymmetricKey& key, const MemoryRegion<byte>& tweak)

   Decrypts an FE1 ciphertext produced by :cpp:func:`fe1_encrypt`; the
   *n*, *key* and *tweak* should be the same as that provided to the
   encryption function. Returns the plaintext.

   Note that there is not any implicit authentication or checking of
   data, so if you provide an incorrect key or tweak the result is
   simply a random integer.

This example encrypts a credit card number with a valid
`Luhn checksum <http://en.wikipedia.org/wiki/Luhn_algorithm>`_ to
another number with the same format, including a correct checksum.

.. literalinclude:: examples/fpe.cpp


Format Preserving Encryption
========================================

Format preserving encryption (FPE) refers to a set of techniques for
encrypting data such that the ciphertext has the same format as the
plaintext. For instance, you can use FPE to encrypt credit card
numbers with valid checksums such that the ciphertext is also an
credit card number with a valid checksum, or similarly for bank
account numbers, US Social Security numbers, or even more general
mappings like English words onto other English words.

The scheme currently implemented in botan is called FE1, and described
in the paper `Format Preserving Encryption
<https://eprint.iacr.org/2009/251>`_ by Mihir Bellare, Thomas
Ristenpart, Phillip Rogaway, and Till Stegers. FPE is an area of
ongoing standardization and it is likely that other schemes will be
included in the future.

To encrypt an arbitrary value using FE1, you need to use a ranking
method. Basically, the idea is to assign an integer to every value you
might encrypt. For instance, a 16 digit credit card number consists of
a 15 digit code plus a 1 digit checksum. So to encrypt a credit card
number, you first remove the checksum, encrypt the 15 digit value
modulo 10\ :sup:`15`, and then calculate what the checksum is for the
new (ciphertext) number. Or, if you were encrypting words in a
dictionary, you could rank the words by their lexicographical order,
and choose the modulus to be the number of words in the dictionary.

The interfaces for FE1 are defined in the header ``fpe_fe1.h``:

.. versionadded:: 2.5.0

.. cpp:class:: FPE_FE1

   .. cpp:function:: FPE_FE1(const BigInt& n, size_t rounds = 5, \
                             bool compat_mode = false,           \
                             std::string mac_algo = "HMAC(SHA-256)")

      Initialize an FPE operation to encrypt/decrypt integers less
      than *n*. It is expected that *n* is trivially factorable into
      small integers. Common usage would be n to be a power of 10.

      Note that the default parameters to this constructor are
      **incompatible** with the ``fe1_encrypt`` and ``fe1_decrypt``
      function originally added in 1.9.17. For compatibility, use
      3 rounds and set ``compat_mode`` to true.

   .. cpp:function:: BigInt encrypt(const BigInt& x, const uint8_t tweak[], size_t tweak_len) const

      Encrypts the value *x* modulo the value *n* using the *key* and *tweak*
      specified. Returns an integer less than *n*. The *tweak* is a value that
      does not need to be secret that parameterizes the encryption function. For
      instance, if you were encrypting a database column with a single key, you
      could use a per-row-unique integer index value as the tweak. The same
      tweak value must be used during decryption.

   .. cpp:function:: BigInt decrypt(const BigInt& x, const uint8_t tweak[], size_t tweak_len) const

      Decrypts an FE1 ciphertext. The *tweak* must be the same as that provided
      to the encryption function. Returns the plaintext integer.

      Note that there is not any implicit authentication or checking of data in
      FE1, so if you provide an incorrect key or tweak the result is simply a
      random integer.

   .. cpp:function:: BigInt encrypt(const BigInt& x, uint64_t tweak)

      Convenience version of encrypt taking an integer tweak.

   .. cpp:function:: BigInt decrypt(const BigInt& x, uint64_t tweak)

      Convenience version of decrypt taking an integer tweak.

There are two functions that handle the entire FE1 encrypt/decrypt operation.
These are the original interface to FE1, first added in 1.9.17. However because
they do the entire setup cost for each operation, they are significantly slower
than the class-based API presented above.

.. warning:: These functions are hardcoded to use 3 rounds, which may be
             insufficient depending on the chosen modulus.

.. cpp:function:: BigInt FPE::fe1_encrypt(const BigInt& n, const BigInt& X, \
             const SymmetricKey& key, const std::vector<uint8_t>& tweak)

    This creates an FPE_FE1 object, sets the key, and encrypts *X* using
    the provided tweak.

.. cpp:function:: BigInt FPE::fe1_decrypt(const BigInt& n, const BigInt& X, \
             const SymmetricKey& key, const std::vector<uint8_t>& tweak)

    This creates an FPE_FE1 object, sets the key, and decrypts *X* using
    the provided tweak.

This example encrypts a credit card number with a valid `Luhn checksum
<https://en.wikipedia.org/wiki/Luhn_algorithm>`_ to another number with the same
format, including a correct checksum.

.. literalinclude:: ../../src/cli/cc_enc.cpp

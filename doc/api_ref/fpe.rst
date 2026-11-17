Format Preserving Encryption
========================================

Format preserving encryption (FPE) refers to a set of techniques for
encrypting data such that the ciphertext has the same format as the
plaintext. For instance, you can use FPE to encrypt credit card
numbers with valid checksums such that the ciphertext is also an
credit card number with a valid checksum, or similarly for bank
account numbers, US Social Security numbers, or even more general
mappings like English words onto other English words.

Two schemes are implemented. FF1 is specified by NIST in `SP 800-38G
<https://csrc.nist.gov/pubs/sp/800/38/g/upd1/final>`_ and is what new
applications should use. FE1 is an older design which was never standardized,
and is not implemented by other libraries.

FF1
----------------------------------------

FF1 encrypts a string of *numerals*, each of which is an integer in the range
[0,radix). The output is a string of numerals of the same length and radix. For
example to encrypt decimal digits use radix 10, with the numerals being the
values of the digits; to encrypt strings of lowercase letters use radix 26 and
map 'a' to 0, 'b' to 1, and so on.

FF1 is always used with AES; the key must be 16, 24, or 32 bytes long.

The security of FF1 depends on there being sufficiently many possible inputs.
As required by the draft revision of SP 800-38G, inputs are rejected unless
there are at least one million possible strings of that length; for example
with radix 10 the input must have at least 6 digits. In addition the input must
always consist of at least 2 numerals. If the set of plausible inputs is small
(for example when most digits of an account number are fixed or guessable), an
attacker who can observe many encryptions may be able to recover plaintexts
no matter which FPE scheme is used.

The interfaces for FF1 are defined in the header ``fpe_ff1.h``:

.. versionadded:: 3.15.0

.. cpp:class:: FPE_FF1

   .. cpp:function:: FPE_FF1(size_t radix)

      Create an FF1 instance for the specified radix, which must be between 2
      and 65536 inclusive.

   .. cpp:function:: void set_key(std::span<const uint8_t> key)

      Set the AES key. This must be called before encrypting or decrypting.

   .. cpp:function:: size_t radix() const

      Return the radix.

   .. cpp:function:: size_t minimum_length() const

      Return the length of the shortest numeral string which will be accepted
      for encryption or decryption.

   .. cpp:function:: void encrypt(std::span<uint16_t> x, std::span<const uint8_t> tweak) const

      Encrypt the numerals in *x*, in place. Each must be less than the radix.
      The *tweak* is a value that does not need to be secret which
      parameterizes the encryption; for example a database row identifier, or
      the digits of an account number which are being left unencrypted. It may
      be empty. Using distinct tweaks where possible is recommended, since
      otherwise equal plaintexts produce equal ciphertexts.

   .. cpp:function:: void decrypt(std::span<uint16_t> x, std::span<const uint8_t> tweak) const

      Decrypt the numerals in *x*, in place. The *tweak* must be the same
      value that was used during encryption.

.. literalinclude:: ../../src/examples/fpe_ff1.cpp
   :language: cpp

Encrypting integers in an arbitrary range
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

FF1 directly handles any set of inputs whose size is a power of the radix, which
covers the common cases such as strings of digits or letters. Occasionally it is
necessary to instead encrypt integers in the range [0,n) for some *n* which is
not of this form, for example an index into a list of 50000 words. This can be
done on top of FF1 using a technique called *cycle walking*:

1. Choose a radix and length such that there are at least *n* possible numeral
   strings. Ideally the number of such strings should not be much larger than
   *n*; using radix 2 ensures it is less than twice *n*.

2. To encrypt *x*, convert it to a numeral string and encrypt it with FF1, then
   convert the result back to an integer.

3. If the result is less than *n*, it is the ciphertext. Otherwise encrypt the
   result again, repeating until a value less than *n* is produced.

Decryption is identical, except using FF1 decryption in each step. The same
tweak is used for every step.

This always terminates, and the expected number of FF1 operations is the number
of possible numeral strings divided by *n*. Note that the number of steps, and
so the time taken, varies depending on the input.

The requirement for a sufficiently large number of possible inputs applies to
*n* itself; a small range does not become safe to encrypt by embedding it in a
larger one.

FE1
----------------------------------------

FE1 is described in the paper `Format Preserving Encryption
<https://eprint.iacr.org/2009/251>`_ by Mihir Bellare, Thomas
Ristenpart, Phillip Rogaway, and Till Stegers.

To encrypt an arbitrary value using FE1, you need to use a ranking
method. Basically, the idea is to assign an integer to every value you
might encrypt. For instance, a 16 digit credit card number consists of
a 15 digit code plus a 1 digit checksum. So to encrypt a credit card
number, you first remove the checksum, encrypt the 15 digit value
modulo 10\ :sup:`15`, and then calculate what the checksum is for the
new (ciphertext) number. Or, if you were encrypting words in a
dictionary, you could rank the words by their lexicographical order,
and choose the modulus to be the number of words in the dictionary.

.. warning::

   This implementation of FE1 is not constant time. In each round the
   intermediate value is encoded at its minimal length before being input to
   the PRF, so the time taken depends on the values being encrypted or
   decrypted. This cannot be changed without altering the output. Avoid FE1
   in settings where such side channels are a concern.

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

This example encrypts a string of dictionary words onto another string of dictionary words:

.. literalinclude:: ../../src/examples/fpe_dictionary.cpp

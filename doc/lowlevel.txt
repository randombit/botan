
The Low-Level Interface
=================================

Botan has two different interfaces. The one documented in this section
is meant more for implementing higher-level types (see the section on
filters, earlier in this manual) than for use by applications. Using
it safely requires a solid knowledge of encryption techniques and best
practices, so unless you know, for example, what CBC mode and nonces
are, and why PKCS #1 padding is important, you should avoid this
interface in favor of something working at a higher level.

Basic Algorithm Abilities
---------------------------------

There are a small handful of functions implemented by most of Botan's
algorithm objects. Among these are:

.. cpp:function:: std::string Algorithm::name()

Returns a human-readable string of the name of this
algorithm. Examples of names returned are "AES-128" and
"HMAC(SHA-512)". You can turn names back into algorithm objects using
the functions in ``lookup.h``.

.. cpp:function:: void Algorithm::clear()

Clear out the algorithm's internal state. A block cipher object will
"forget" its key, a hash function will "forget" any data put into it,
etc. The object will look and behave as it did when you initially
allocated it.

.. cpp:function:: T* Algorithm::clone()

This function is central to Botan's name-based interface. The
``clone`` has many different return types, such as ``BlockCipher``\*
and ``HashFunction``\*, depending on what kind of object it is called
on. Note that unlike Java's clone, this returns a new object in a
"pristine" state; that is, operations done on the initial object
before calling ``clone`` do not affect the initial state of the new
clone.

Cloned objects can (and should) be deallocated with the C++ ``delete``
operator.

Keys and IVs
---------------------------------

Both symmetric keys and initialization values can be considered byte
(or octet) strings. These are represented by

.. cpp:class:: OctetString

   Also known as ``SymmetricKey`` and ``InitializationVector``, when
   you want to express intent.

   .. cpp:function:: OctetString(RandomNumberGenerator& rng, size_t length)

      This constructor creates a new random key *length* bytes long
      using the random number generator.

   .. cpp:function:: OctetString(std::string str)

      The argument *str* is assumed to be a hex string; it is
      converted to binary and stored. Whitespace is ignored.

   .. cpp:function:: OctetString(const byte* input, size_t length)

      This constructor copies its input.

   .. cpp:function:: as_string() const

      Returns the hex representation of the key or IV

Symmetrically Keyed Algorithms
---------------------------------

Block ciphers, stream ciphers, and MACs are all keyed operations; to
be useful, they have to be set to use a particular key, which is a
randomly chosen string of bits of a specified length.  The length
required by any particular algorithm may vary, depending on both the
algorithm specification and the implementation. You can query any
botan object to find out what key length(s) it supports.

To make this similarity in terms of keying explicit, all algorithms of
those types are derived from the :cpp:class`SymmetricAlgorithm` base.
This type provides functions for setting the key, and querying
restrictions on the size of the key.

.. cpp:class:: SymmetricAlgorithm

   .. cpp:function:: void set_key(const byte* key, size_t length)

   .. cpp:function:: void set_key(const SymmetricKey& key)

     This sets the key to the value specified. Most algorithms only
     accept keys of certain lengths. If you attempt to call
     ``set_key`` with a key length that is not supported, the
     exception ``Invalid_Key_Length`` will be thrown.

     In all cases, ``set_key`` must be called on an object before any
     data processing (encryption, decryption, etc) is done by that
     object. If this is not done, the results are undefined.

   .. cpp:function:: bool valid_keylength(size_t length) const

     This function returns true if and only if *length* is a valid
     keylength for the algorithm.

   .. cpp:function:: size_t minimum_keylength() const

     Return the smallest key length (in bytes) that is acceptible for the
     algorithm.

   .. cpp:function:: size_t maximum_keylength() const

     Return the largest key length (in bytes) that is acceptible for the
     algorithm

Block Ciphers
---------------------------------

All block ciphers classes in botan are subclasses of

.. cpp:class:: BlockCipher

   Which subclasses the :cpp:class:`SymmetricAlgorithm` interface.

   .. cpp:function:: size_t block_size() const

      Returns the block size of the cipher in bytes

   .. cpp:function:: void encrypt_n(const byte* in, \
         byte* out, size_t n) const

      Encrypt *n* blocks of data, taking the input from the array *in*
      and placing the ciphertext into *out*. The two pointers may be
      identical, but should not overlap ranges.

   .. cpp:function:: void encrypt(const byte* in, byte* out) const

      Encrypt a single block, taking the input from *in* and placing
      it in *out*. Acts like :cpp:func:`encrypt_n`\ (in, out, 1).

   .. cpp:function:: void encrypt(byte* block) const

      Identical to :cpp:func:`encrypt`\ (block, block)

   .. cpp:function:: void decrypt_n(const byte* in, byte out, size_t n) const

      Decrypt *n* blocks of data, taking the input from *in* and
      placing the plaintext in *out*. The two pointers may be
      identical, but should not overlap ranges.

   .. cpp:function:: void decrypt(const byte* in, byte* out) const

      Decrypt a single block, taking the input from *in* and placing it
      in *out*. Acts like :cpp:func:`decrypt_n`\ (in, out, 1).

   .. cpp:function:: void decrypt(byte* block) const

      Identical to :cpp:func:`decrypt`\ (block, block)

Stream Ciphers
---------------------------------

Stream ciphers are somewhat different from block ciphers, in that
encrypting data results in changing the internal state of the
cipher. Also, you may encrypt any length of data in one go (in byte
amounts).

.. cpp:function:: void StreamCipher::encrypt(const byte* in, byte* out, size_t length)

.. cpp:function:: void StreamCipher::encrypt(byte* data, size_t length)

Stream ciphers implement the ``SymmetricAlgorithm`` interface.

Hash Functions / Message Authentication Codes
----------------------------------------------

Hash functions take their input without producing any output, only
producing anything when all input has already taken place. MACs are
very similar, but are additionally keyed. Both of these are derived
from the base class ``BufferedComputation``, which has the following
functions.

.. cpp:function:: size_t BufferedComputation::output_length()

Return the size of the output of this function.

.. cpp:function:: void BufferedComputation::update(const byte* input, size_t length)

.. cpp:function:: void BufferedComputation::update(byte input)

.. cpp:function:: void BufferedComputation::update(const std::string& input)

Updates the hash/mac calculation with *input*.

.. cpp:function:: void BufferedComputation::final(byte* out)

.. cpp:function:: SecureVector<byte> BufferedComputation::final()

Complete the hash/MAC calculation and place the result into ``out``.
For the argument taking an array, exactly ``output_length`` bytes will
be written. After you call ``final``, the hash function is reset to
its initial state, so it may be reused immediately.

The second method of using final is to call it with no arguments at
all, as shown in the second prototype. It will return the hash/mac
value in a memory buffer.

There is also a pair of functions called ``process``. They are a
combination of a single ``update``, and ``final``. Both versions
return the final value, rather than placing it an array. Calling
``process`` with a single byte value isn't available, mostly because
it would rarely be useful.

A MAC can be viewed (in most cases) as a keyed hash function, so
classes that are derived from ``MessageAuthenticationCode`` have
``update`` and ``final`` classes just like a ``HashFunction`` (and
like a ``HashFunction``, after ``final`` is called, it can be used to
make a new MAC right away; the key is kept around).

A MAC has the ``SymmetricAlgorithm`` interface in addition to the
``BufferedComputation`` interface.

Checksums
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Checksums are very similar to hash functions, and in fact share the
same interface. But there are some significant differences, the major
ones being that the output size is very small (usually in the range of
2 to 4 bytes), and is not cryptographically secure. But for their
intended purpose (error checking), they perform very well. Some
examples of checksums included in Botan are the Adler32 and CRC32
checksums.

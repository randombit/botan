
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

.. cpp:function:: std::string name()

Returns a human-readable string of the name of this
algorithm. Examples of names returned are "AES-128" and
"HMAC(SHA-512)". You can turn names back into algorithm objects using
the functions in ``lookup.h``.

.. cpp:function:: void clear()

Clear out the algorithm's internal state. A block cipher object will
"forget" its key, a hash function will "forget" any data put into it,
etc. The object will look and behave as it did when you initially
allocated it.

.. cpp:function:: T* clone()

The ``clone`` has many different return types, such as
``BlockCipher``\* and ``HashFunction``\*, depending on what kind of
object it is called on. Note that unlike Java's clone, this returns a
new object in a "pristine" state; that is, operations done on the
initial object before calling ``clone`` do not affect the initial
state of the new clone.

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

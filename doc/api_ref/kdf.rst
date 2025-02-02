
.. _key_derivation_function:

Key Derivation Functions (KDF)
========================================

Key derivation functions are used to turn some amount of shared secret material
into uniform random keys suitable for use with symmetric algorithms. An example
of an input which is useful for a KDF is a shared secret created using
Diffie-Hellman key agreement.

Typically a KDF is also used with a *salt* and a *label*. The *salt* should be
some random information which is available to all of the parties that would need
to use the KDF; this could be performed by setting the salt to some kind of
session identifier, or by having one of the parties generate a random salt and
including it in a message.

The *label* is used to bind the KDF output to some specific context. For
instance if you were using the KDF to derive a specific key referred to as the
"message key" in the protocol description, you might use a label of "FooProtocol
v2 MessageKey". This labeling ensures that if you accidentally use the same
input key and salt in some other context, you still use different keys in the
two contexts.

.. cpp:class:: KDF

  .. cpp:function:: std::unique_ptr<KDF> KDF::create(const std::string& algo)

      Create a new KDF object. Returns nullptr if the named key derivation
      function was not available

  .. cpp:function:: std::unique_ptr<KDF> KDF::create_or_throw(const std::string& algo)

      Create a new KDF object. Throws an exception if the named key derivation
      function was not available

  .. cpp:function:: void KDF::derive_key(std::span<uint8_t> key, \
                                         std::span<const uint8_t> secret, \
                                         std::span<const uint8_t> salt, \
                                         std::span<const uint8_t> label) const

      Performs a key derivation using ``secret`` as secret input, and ``salt``,
      and ``label`` as deversifiers. The passed ``key`` buffer is fully filled
      with key material derived from the inputs.

  .. cpp:function:: template<concepts::resizable_byte_buffer T = secure_vector<uint8_t>> \
      T KDF::derive_key(size_t key_len, \
                        std::span<const uint8_t> secret, \
                        std::span<const uint8_t> salt, \
                        std::span<const uint8_t> label) const

      This version is parameterized to the output buffer type, so it can be used
      to return a ``std::vector``, a ``secure_vector``, or anything else
      satisfying the ``resizable_byte_buffer`` concept.

  .. cpp:function:: template<size_t key_len> \
      std::array<uint8_t, key_len> KDF::derive_key(std::span<const uint8_t> secret, \
                                                   std::span<const uint8_t> salt, \
                                                   std::span<const uint8_t> label) const

      This version returns the key material as a std::array<> of ``key_len``
      bytes.

   All variations on the same theme. Deterministically creates a
   uniform random value from *secret*, *salt*, and *label*, whose
   meaning is described above.

.. _key_derivation_function_example:

Code Example
------------

An example demonstrating using the API to hash a secret using HKDF

.. literalinclude:: /../src/examples/kdf.cpp
   :language: cpp


Available KDFs
-------------------

Botan includes many different KDFs simply because different protocols and.
standards have created subtly different approaches to this problem. For new
code, use HKDF which is conservative, well studied, widely implemented and NIST
approved. There is no technical reason (besides compatibility) to choose any
other KDF.

HKDF
~~~~~

Defined in RFC 5869, HKDF uses HMAC to process inputs. Also available
are variants HKDF-Extract and HKDF-Expand. HKDF is the combined
Extract+Expand operation. Use the combined HKDF unless you need
compatibility with some other system.

Available if ``BOTAN_HAS_HKDF`` is defined.

Algorithm specification names:

- ``HKDF(<MessageAuthenticationCode|HashFunction>)``, e.g. ``HKDF(HMAC(SHA-256))``
- ``HKDF-Extract(<MessageAuthenticationCode|HashFunction>)``
- ``HKDF-Expand(<MessageAuthenticationCode|HashFunction>)``

If a ``HashFunction`` is provided as an argument,
it will create ``HMAC(HashFunction)`` as the ``MessageAuthenticationCode``.
I.e. ``HKDF(SHA-256)`` will result in ``HKDF(HMAC(SHA-256))``.

KDF1-18033
~~~~~~~~~~~~

KDF1 from ISO 18033-2. Very similar to (but incompatible with) KDF2.

Available if ``BOTAN_HAS_KDF1_18033`` is defined.

Algorithm specification name:
``KDF1-18033(<HashFunction>)``, e.g. ``KDF1-18033(SHA-512)``

KDF1
~~~~~~

KDF1 from IEEE 1363. It can only produce an output at most the length
of the hash function used.

Available if ``BOTAN_HAS_KDF1`` is defined.

Algorithm specification name:
``KDF1(<HashFunction>)``, e.g. ``KDF1(SHA-512)``

KDF2
~~~~~

KDF2 comes from IEEE 1363. It uses a hash function.

Available if ``BOTAN_HAS_KDF2`` is defined.

Algorithm specification name:
``KDF2(<HashFunction>)``, e.g. ``KDF2(SHA-512)``

X9.42 PRF
~~~~~~~~~~

A KDF from ANSI X9.42. Sometimes used for Diffie-Hellman. However it is
overly complicated and is fixed to use only SHA-1.

Available if ``BOTAN_HAS_X942_PRF`` is defined.

.. warning::
   X9.42 PRF is deprecated and will be removed in a future major release.

Algorithm specification name:
``X9.42-PRF(<OID>)``,
e.g. ``X9.42-PRF(KeyWrap.TripleDES)``, ``X9.42-PRF(1.2.840.113549.1.9.16.3.7)``

SP800-56A
~~~~~~~~~~

KDF from NIST SP 800-56Ar2 or One-Step KDF of SP 800-56Cr2.

Available if ``BOTAN_HAS_SP800_56A`` is defined.

Algorithm specification names:

- ``SP800-56A(<HashFunction>)``, e.g. ``SP800-56A(SHA-256)``
- ``SP800-56A(HMAC(<HashFunction>))``, e.g. ``SP800-56A(HMAC(SHA-256))``
- ``SP800-56A(KMAC-128)`` or ``SP800-56A(KMAC-256)``

SP800-56C
~~~~~~~~~~

Two-Step KDF from NIST SP 800-56Cr2.

Available if ``BOTAN_HAS_SP800_56C`` is defined.

Algorithm specification name:
``SP800-56C(<MessageAuthenticationCode|HashFunction>)``,
e.g. ``SP800-56C(HMAC(SHA-256))``

If a ``HashFunction`` is provided as an argument,
it will create ``HMAC(HashFunction)`` as the ``MessageAuthenticationCode``.
I.e. ``SP800-56C(SHA-256)`` will result in ``SP800-56C(HMAC(SHA-256))``.

SP800-108
~~~~~~~~~~

KDFs from NIST SP 800-108. Variants include "SP800-108-Counter",
"SP800-108-Feedback" and "SP800-108-Pipeline".

SP800-108 does not explicitly specify the encoding width of the internally used
counter and output length values. As those values are incorporated into the key
derivation, applications can optionally specify their encoding bit lengths as of
Botan 3.7.0. Values of 8, 16, 24, and 32 are supported and Botan will always
encode in big-endian byte order. If not otherwise specified, both fields are
encoded using 32 bits.

Available if ``BOTAN_HAS_SP800_108`` is defined.

Algorithm specification names:

- ``SP800-108-Counter(<MessageAuthenticationCode|HashFunction>[,<counter bit length>[,<output length bit length>]])``,
  e.g. ``SP800-108-Counter(HMAC(SHA-256),8,24)``
- ``SP800-108-Feedback(<MessageAuthenticationCode|HashFunction>[,<counter bit length>[,<output length bit length>]])``
- ``SP800-108-Pipeline(<MessageAuthenticationCode|HashFunction>[,<counter bit length>[,<output length bit length>]])``

If a ``HashFunction`` is provided as an argument,
it will create ``HMAC(HashFunction)`` as the ``MessageAuthenticationCode``.
If no field encoding lengths are specified, both are defaulted to 32 bits.
I.e. ``SP800-108-Counter(SHA-256)`` will result in
``SP800-108-Counter(HMAC(SHA-256),32,32)``.

TLS 1.2 PRF
~~~~~~~~~~~

Implementation of the Pseudo-Random Function as used in TLS 1.2.

Available if ``BOTAN_HAS_TLS_V12_PRF`` is defined.

Algorithm specification name:
``TLS-12-PRF(<MessageAuthenticationCode|HashFunction>)``,
e.g. ``TLS-12-PRF(HMAC(SHA-256))``

If a ``HashFunction`` is provided as an argument,
it will create ``HMAC(HashFunction)`` as the ``MessageAuthenticationCode``.
I.e. ``TLS-12-PRF(SHA-256)`` will result in ``TLS-12-PRF(HMAC(SHA-256))``.


.. _key_derivation_function:

Key Derivation Functions (KDF)
========================================

Key derivation functions are used to turn some amount of shared secret
material into uniform random keys suitable for use with symmetric
algorithms. An example of an input which is useful for a KDF is a
shared secret created using Diffie-Hellman key agreement.

.. cpp:class:: KDF

  .. cpp:function:: secure_vector<uint8_t> derive_key( \
                                    const uint8_t secret[], \
                                    size_t secret_len, \
                                    const uint8_t salt[], \
                                    size_t salt_len, \
                                    const uint8_t label[], \
                                    size_t label_len) const

  .. cpp:function:: secure_vector<uint8_t> derive_key( \
     size_t key_len, const std::vector<uint8_t>& secret, \
     const std::vector<uint8_t>& salt, \
     const std::vector<uint8_t>& label) const

  .. cpp:function:: secure_vector<uint8_t> derive_key( \
     size_t key_len, const std::vector<uint8_t>& secret, \
     const uint8_t* salt, size_t salt_len) const

  .. cpp:function:: secure_vector<uint8_t> derive_key( \
     size_t key_len, const uint8_t* secret, size_t secret_len, \
     const std::string& salt) const

   All variations on the same theme. Deterministically creates a
   uniform random value from *secret*, *salt*, and *label*.

   Typically *label* is a fixed used to identity a protocol context,
   for example "FooProtocol v1.0 key derivation", and *salt* is chosen
   randomly or is some string associated with the current protocol
   instance, for example a session identifier.

You can create a :cpp:class:`KDF` using the static function

.. cpp:function:: std::unique_ptr<KDF> KDF::create(const std::string& algo)


Available KDFs
-------------------

Botan includes many different KDFs simply because different protocols and.
standards have created subtly different approaches to this problem. For new
code, use HKDF which is conservative, well studied, widely implemented and NIST
approved. There is no technical reason (besides compatability) to choose any
other KDF.

HKDF
~~~~~

Defined in RFC 5869, HKDF uses HMAC to process inputs. Also available
are variants HKDF-Extract and HKDF-Expand. HKDF is the combined
Extract+Expand operation. Use the combined HKDF unless you need
compatibility with some other system.

Available if ``BOTAN_HAS_HKDF`` is defined.

KDF2
~~~~~

KDF2 comes from IEEE 1363. It uses a hash function.

Available if ``BOTAN_HAS_KDF2`` is defined.

KDF1-18033
~~~~~~~~~~~~

KDF1 from ISO 18033-2. Very similar to (but incompatible with) KDF2.

Available if ``BOTAN_HAS_KDF1_18033`` is defined.

KDF1
~~~~~~

KDF1 from IEEE 1363. It can only produce an output at most the length
of the hash function used.

Available if ``BOTAN_HAS_KDF1`` is defined.

X9.42 PRF
~~~~~~~~~~

A KDF from ANSI X9.42. Sometimes used for Diffie-Hellman. However it is
overly complicated and is fixed to use only SHA-1.

Available if ``BOTAN_HAS_X942_PRF`` is defined.

.. warning::
   X9.42 PRF is deprecated and will be removed in a future major release.

SP800-108
~~~~~~~~~~

KDFs from NIST SP 800-108. Variants include "SP800-108-Counter",
"SP800-108-Feedback" and "SP800-108-Pipeline".

Available if ``BOTAN_HAS_SP800_108`` is defined.

SP800-56A
~~~~~~~~~~

KDF from NIST SP 800-56A.

Available if ``BOTAN_HAS_SP800_56A`` is defined.

SP800-56C
~~~~~~~~~~

KDF from NIST SP 800-56C.

Available if ``BOTAN_HAS_SP800_56C`` is defined.


.. _key_derivation_function:

Key Derivation Functions
========================================

Key derivation functions are used to turn some amount of shared secret
material into uniform random keys suitable for use with symmetric
algorithms. An example of an input which is useful for a KDF is a
shared secret created using Diffie-Hellman key agreement.

.. cpp:class:: KDF

  .. cpp:function:: secure_vector<uint8_t> derive_key( \
     size_t key_len, const std::vector<uint8_t>& secret, \
     const std::string& salt = "") const

  .. cpp:function:: secure_vector<uint8_t> derive_key( \
     size_t key_len, const std::vector<uint8_t>& secret, \
     const std::vector<uint8_t>& salt) const

  .. cpp:function:: secure_vector<uint8_t> derive_key( \
     size_t key_len, const std::vector<uint8_t>& secret, \
     const uint8_t* salt, size_t salt_len) const

  .. cpp:function:: secure_vector<uint8_t> derive_key( \
     size_t key_len, const uint8_t* secret, size_t secret_len, \
     const std::string& salt) const

   All variations on the same theme. Deterministically creates a
   uniform random value from *secret* and *salt*. Typically *salt* is
   a label or identifier, such as a session id.

You can create a :cpp:class:`KDF` using

.. cpp:function:: KDF* get_kdf(const std::string& algo_spec)


Available KDFs
-------------------

Botan includes many different KDFs simply because different protocols and
standards have created subtly different approaches to this problem. For new
code, use HKDF which is conservative, well studied, widely implemented and NIST
approved.

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

A KDF from ANSI X9.42. Sometimes used for Diffie-Hellman.

Available if ``BOTAN_HAS_X942_PRF`` is defined.

.. warning::
   Support for X9.42 KDF is deprecated and will be removed in a future major release.

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

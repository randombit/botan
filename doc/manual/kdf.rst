
.. _key_derivation_function:

Key Derivation Functions
========================================

Key derivation functions are used to turn some amount of shared secret
material into uniform random keys suitable for use with symmetric
algorithms. An example of an input which is useful for a KDF is a
shared secret created using Diffie-Hellman key agreement.

.. cpp:class:: KDF

  .. cpp:function:: secure_vector<byte> derive_key( \
     size_t key_len, const std::vector<byte>& secret, \
     const std::string& salt = "") const

  .. cpp:function:: secure_vector<byte> derive_key( \
     size_t key_len, const std::vector<byte>& secret, \
     const std::vector<byte>& salt) const

  .. cpp:function:: secure_vector<byte> derive_key( \
     size_t key_len, const std::vector<byte>& secret, \
     const byte* salt, size_t salt_len) const

  .. cpp:function:: secure_vector<byte> derive_key( \
     size_t key_len, const byte* secret, size_t secret_len, \
     const std::string& salt) const

   All variations on the same theme. Deterministically creates a
   uniform random value from *secret* and *salt*. Typically *salt* is
   a lable or identifier, such as a session id.

You can create a :cpp:class:`KDF` using

.. cpp:function:: KDF* get_kdf(const std::string& algo_spec)


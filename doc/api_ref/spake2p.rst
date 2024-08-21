SPAKE2+ Password Authenticated Key Exchange
=============================================

.. versionadded:: 3.10.0

TODO needs to be updated for SPAKE2+

An implementation of SPAKE2+ password authenticated key exchange
compatible with RFC 9833 is included.

SPAKE2 requires each peer know its "role" within the protocol, namely being A
or B. This is common in most protocols; for example in a client/server
architecture, the client could be A and the server B.

This implementation of SPAKE2 does not include the key confirmation step. Thus,
on its own, there is no guarantee that the two peers actually share the same
secret key. Normally the SPAKE2 shared secret is subsequently used to encrypt
one or more messages; this serves to confirm the key. It is possible to
implement RFC 9832 compatible key confirmation, as described in RFC 9832 Section 4.

Each instance is configured with a set of parameters

.. cpp:class:: SPAKE2::Parameters

   .. cpp:function:: SPAKE2::Parameters(const EC_Group& group, \
                        std::string_view shared_secret, \
                        std::span<const uint8_t> a_identity = {}, \
                        std::span<const uint8_t> b_identity = {}, \
                        std::span<const uint8_t> context = {}, \
                        std::string_view hash = "SHA-512", \
                        bool per_user_params = true)

      Constructs a new set of parameters.

      The elliptic curve group should typically be P-256, P-384, or P-521.

      The ``shared_secret`` is the low entropy user secret. This is hashed using
      Argon2id to generate the SPAKE2 ``w`` parameter.

      The identities of the two peers are specified in ``a_identity`` and
      ``b_identity``. These can be left empty if there is no possible identity;
      however even the strings "client" and "server" would be preferable rather
      than leaving them completely blank.

      The ``context`` is some arbitrary bytestring which is included when hashing
      the shared secret. It can be left empty, or can be used to identity eg
      the protocol in use.

      The ``hash_fn`` parameter specifies a hash function to use. Use SHA-512.

      If ``per_user_params`` is true, then SPAKE2 will proceed using system
      parameters N/M which were generated using RFC 9380 hash to curve using the
      identities and context string as inputs. This makes SPAKE2 "quantum
      annoying"; baseline SPAKE2 can be broken by anyone who can recover the
      discrete logarithms of the fixed N/M parameters included in the RFC. This
      makes life difficult for an attacker who can compute discrete logarithms,
      but cannot do so cheaply.

.. cpp:enum-class:: SPAKE2::PeerId

   .. cpp:enumerator:: SPAKE2::PeerId::PeerA

   .. cpp:enumerator:: SPAKE2::PeerId::PeerB


.. cpp:class:: SPAKE2::Context

   .. cpp:function:: SPAKE2::Context(SPAKE2::PeerId whoami, \
                     const SPAKE2::Parameters& params, \
                     RandomNumberGenerator& rng)

      Prepare for a SPAKE2 exchange

   .. cpp:function:: std::vector<uint8_t> generate_message()

      Proceed with the protocol. Generate a message, which must be sent
      to the peer.

   .. cpp:function:: secure_vector<uint8_t> process_message(std::span<const uint8_t> peer_message)

      Complete the key exchange, returning the shared secret. Will throw an exception
      if an error occurs (eg the peer message is not formatted correctly)

Code Example: SPAKE2 PAKE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The example below demonstrates using SPAKE2 to perform a password authenticated
key exchange.

.. literalinclude:: /../src/examples/spake2.cpp
   :language: cpp

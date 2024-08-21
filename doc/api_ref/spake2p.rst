SPAKE2+ Password Authenticated Key Exchange
=============================================

.. versionadded:: 3.13.0

An implementation of the SPAKE2+ password authenticated key exchange, compatible with
RFC 9383, is included.

SPAKE2+ allows two peers who share a (possibly low entropy) secret such as a password to
agree on a strong shared secret key. An attacker who observes or modifies the exchange
learns nothing about the password (beyond excluding a single guess per protocol
execution) or the session key.

SPAKE2+ is an *augmented* PAKE, meaning the two sides are asymmetric. The *prover*
(typically a client) knows the password itself, while the *verifier* (typically a
server) stores only a *registration record* derived from the password. An attacker who
steals the registration record cannot impersonate the prover without first performing a
successful dictionary attack against the record.

The protocol consists of two phases:

* *Registration* (performed once, over some trusted channel): the prover derives its
  secret values from the password, and provides the resulting registration record to the
  verifier.

* *Online authentication* (performed per session): the two sides exchange key shares and
  key confirmation messages, resulting in a mutually authenticated shared secret.

The online message flow is::

    Prover                             Verifier

    ProverContext::generate_message
                    --- shareP -->
                                       VerifierContext::process_message
                    <-- shareV || confirmV ---
    ProverContext::process_message
                    --- confirmP -->
                                       VerifierContext::verify_confirmation

After the final step both sides call ``shared_secret`` to obtain the session key
(``K_shared`` in RFC 9383).

Some protocols which embed SPAKE2+ perform the prover's key confirmation themselves
rather than exchanging ``confirmP``. For example in the proposed PAKE extension for TLS
1.3 (draft-bmw-tls-pake13), the server acts as the verifier, feeds the shared secret
into the TLS key schedule immediately after processing the prover's key share, and the
TLS handshake takes the place of ``confirmP``. To support such protocols, the verifier
may call ``skip_confirmation`` in place of ``verify_confirmation``; see below.

System Parameters
-------------------

.. cpp:class:: SPAKE2p::SystemParameters

   Specifies the ciphersuite in use, namely the elliptic curve group, the SPAKE2+
   ``M``/``N`` group elements, and the hash function. The hash function also fixes the
   KDF (HKDF) and the key confirmation MAC (HMAC).

   Static factory functions ``rfc9383_p256_sha256``, ``rfc9383_p256_sha512``,
   ``rfc9383_p384_sha256``, ``rfc9383_p384_sha512``, and ``rfc9383_p521_sha512`` return
   the standard ciphersuites from RFC 9383.

   .. cpp:function:: static SystemParameters custom(const EC_Group& group, \
                        std::span<const uint8_t> seed, \
                        std::string_view hash_fn)

      Creates custom system parameters for an arbitrary group, deriving the ``M``/``N``
      elements from the seed using hash to curve (which not all groups support). Both
      peers must use the same seed.

      If the seed includes the identities of the participants, this additionally makes
      the scheme "quantum annoying": an attacker with a discrete logarithm oracle must
      compute a new discrete logarithm for each (prover, verifier) pair they wish to
      attack, rather than being able to attack any user after computing the discrete
      logarithms of the fixed ``M``/``N`` elements once.

Registration
--------------

.. cpp:class:: SPAKE2p::ProverSecret

   The secret values (``w0`` and ``w1`` in RFC 9383) which the prover derives
   from the password.

   .. cpp:function:: static ProverSecret from_password(const SystemParameters& params, \
                        std::string_view password, \
                        std::span<const uint8_t> prover_id, \
                        std::span<const uint8_t> verifier_id, \
                        std::span<const uint8_t> salt)

      Derives the prover secret from a password using Argon2id, with the
      memory-constrained parameters recommended in RFC 9106 (m=64 MiB, t=3, p=4).

      Following RFC 9383, the Argon2id passphrase input is the concatenation
      ``len(pw)|| pw || len(idProver) || idProver || len(idVerifier) || idVerifier``, where
      each length is an 8-byte little-endian count of bytes; the salt is provided to
      Argon2id directly. The output is split into two halves, each of which is reduced
      modulo the group order.

      The identities and the salt may be empty; if a salt is available it should be
      used, since it prevents precomputed dictionary attacks.

   .. cpp:function:: static ProverSecret from_prehashed(EC_Scalar w0, EC_Scalar w1)

      Creates a prover secret from already derived scalars, for applications which
      require a password hashing scheme other than the default one.  The scalars must be
      derived from the password in a way that produces uniformly random values modulo
      the group order; see RFC 9383 section 3.2 for the requirements.

   .. cpp:function:: RegistrationRecord registration_record(RandomNumberGenerator& rng) const

      Computes the registration record (``w0`` and ``L = w1*P``) which is provided to
      the verifier during registration.

   .. cpp:function:: static ProverSecret deserialize(const SystemParameters& params, \
                        std::span<const uint8_t> secret)

   .. cpp:function:: secure_vector<uint8_t> serialize() const

      Serialization, if the prover wishes to store the derived secret rather than
      rederiving it from the password each time. The serialized secret is password
      equivalent, so it should be encrypted if stored persistently.

.. cpp:class:: SPAKE2p::RegistrationRecord

   The information (``w0`` and ``L`` in RFC 9383) which the verifier stores in order to
   later authenticate the prover.

   .. cpp:function:: static RegistrationRecord from_password(const SystemParameters& params, \
                        std::string_view password, \
                        std::span<const uint8_t> prover_id, \
                        std::span<const uint8_t> verifier_id, \
                        std::span<const uint8_t> salt, \
                        RandomNumberGenerator& rng)

      Performs password registration in a single step, equivalent to
      ``ProverSecret::from_password`` followed by ``registration_record``.

   .. cpp:function:: static RegistrationRecord deserialize(const SystemParameters& params, \
                        std::span<const uint8_t> record)

   .. cpp:function:: secure_vector<uint8_t> serialize() const

      Serialization, for storage by the verifier. While the record does not allow direct
      impersonation of the prover, it does allow offline password guessing attacks, so
      it should be encrypted if possible.

Online Authentication
-----------------------

.. cpp:class:: SPAKE2p::ProverContext

   .. cpp:function:: ProverContext(const SystemParameters& params, \
                     const ProverSecret& secret, \
                     std::span<const uint8_t> prover_id, \
                     std::span<const uint8_t> verifier_id, \
                     std::span<const uint8_t> context = {})

      Prepares an execution of the protocol. The identities and the context must be
      agreed upon by both peers, and the identities must match the values used during
      registration. Even if there is no natural identity available, using fixed labels
      such as "client" and "server" is preferable to leaving the identities empty. The
      context should identify the application and protocol version; it may be empty.

   .. cpp:function:: std::vector<uint8_t> generate_message(RandomNumberGenerator& rng)

      Returns the prover's key share (``shareP``), which is sent to the verifier. Can be
      called only once.

   .. cpp:function:: std::vector<uint8_t> process_message(std::span<const uint8_t> peer_message, \
                     RandomNumberGenerator& rng)

      Consumes the verifier's response (``shareV || confirmV``) and returns the prover's
      key confirmation (``confirmP``), which is sent to the verifier. Throws
      ``Decoding_Error`` if the message is malformed, or ``Invalid_Authentication_Tag``
      if the key confirmation is wrong (typically meaning the passwords do not match).

   .. cpp:function:: secure_vector<uint8_t> shared_secret() const

      Returns the shared secret. May be called only after ``process_message`` has
      succeeded.

.. cpp:class:: SPAKE2p::VerifierContext

   .. cpp:function:: VerifierContext(const SystemParameters& params, \
                     const RegistrationRecord& record, \
                     std::span<const uint8_t> prover_id, \
                     std::span<const uint8_t> verifier_id, \
                     std::span<const uint8_t> context = {})

      Prepares an execution of the protocol; see ``ProverContext`` above for the
      requirements on the identities and context.

   .. cpp:function:: std::vector<uint8_t> process_message(std::span<const uint8_t> peer_message, \
                     RandomNumberGenerator& rng)

      Consumes the prover's key share (``shareP``) and returns the verifier's response
      (``shareV || confirmV``), which is sent to the prover. Can be called only
      once. Throws ``Decoding_Error`` if the key share is malformed.

   .. cpp:function:: void verify_confirmation(std::span<const uint8_t> confirmation)

      Checks the prover's key confirmation (``confirmP``). Throws ``Invalid_Authentication_Tag``
      if the confirmation is wrong, meaning the prover does not know the password.

   .. cpp:function:: void skip_confirmation()

      Can be called after ``process_message``, in place of ``verify_confirmation``, to
      allow extracting the shared secret without having checked the prover's key
      confirmation.

      .. warning::

         After calling this, nothing is known about the peer; only a prover which knows
         the password can compute the same shared secret, but no evidence of this has
         been received. It is intended solely for protocols which embed SPAKE2+ and
         perform the prover's key confirmation themselves, such as the proposed PAKE
         extension for TLS 1.3, where the TLS handshake takes the place of
         ``confirmP``. Anywhere else, use ``verify_confirmation``.

   .. cpp:function:: secure_vector<uint8_t> shared_secret() const

      Returns the shared secret. May be called only after ``verify_confirmation`` has
      succeeded, or after ``skip_confirmation``.

Code Example: SPAKE2+ PAKE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The example below demonstrates using SPAKE2+ to perform a password authenticated key
exchange.

.. literalinclude:: /../src/examples/spake2p.cpp
   :language: cpp

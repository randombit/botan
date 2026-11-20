Hybrid Public Key Encryption (HPKE)
========================================

.. versionadded:: 3.14.0

HPKE (:rfc:`9180`) encrypts messages to a public key, by combining a key
encapsulation mechanism (KEM), a key derivation function (KDF), and an AEAD.
It is the encryption scheme used by, among others, TLS Encrypted Client Hello
(:rfc:`9849`), Messaging Layer Security (:rfc:`9420`), and Oblivious HTTP
(:rfc:`9458`).

An HPKE exchange starts with the sender encapsulating a fresh shared secret
to the recipient's public key. Both sides then derive an *encryption context*
from the shared secret, an application-provided binding string (the *info*),
and the negotiated ciphersuite. The sender's context can encrypt ("seal") a
sequence of messages which the recipient's context decrypts ("opens") in the
same order, and both contexts can also export additional shared secrets for
use elsewhere in the application.

Besides the Diffie-Hellman based KEMs of RFC 9180, the post-quantum KEMs of
`draft-ietf-hpke-pq <https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/>`_
are available in an experimental module which is not part of a default
build; see :ref:`hpke_pq_kems`.

HPKE defines four modes. In *base* mode the sender is anonymous. The *psk*
mode additionally authenticates the sender via a pre-shared key, *auth* mode
via the sender's own KEM key pair, and *auth_psk* combines both. The *auth*
and *auth_psk* modes are only supported by the Diffie-Hellman based KEMs.

All functionality is in ``botan/hpke.h``, within the namespace
``Botan::HPKE``.

Ciphersuites
----------------------------------------

An HPKE ciphersuite is a triple of KEM, KDF, and AEAD, which are negotiated
or configured as 16-bit IANA codepoints. The identifier types below are thin
value types around these codepoints. They can represent *any* 16-bit value,
including codepoints unknown to the library; this is necessary when parsing
protocol structures such as an ECH configuration, which may contain suites
(including GREASE values) that the local build does not support. Whether an
identifier is usable is a separate question from whether it is representable:

* ``is_known`` is true if this version of the library knows the codepoint.
* ``is_available`` is true if the required algorithms are compiled into the
  build.

The known KEMs:

==========================  =========  ==========
KEM                         Codepoint  Auth modes
==========================  =========  ==========
DHKEM(P-256, HKDF-SHA256)   0x0010     yes
DHKEM(P-384, HKDF-SHA384)   0x0011     yes
DHKEM(P-521, HKDF-SHA512)   0x0012     yes
DHKEM(X25519, HKDF-SHA256)  0x0020     yes
DHKEM(X448, HKDF-SHA512)    0x0021     yes
ML-KEM-512                  0x0040     no
ML-KEM-768                  0x0041     no
ML-KEM-1024                 0x0042     no
MLKEM768-P256               0x0050     no
MLKEM1024-P384              0x0051     no
MLKEM768-X25519             0x647A     no
==========================  =========  ==========

The known KDFs are HKDF-SHA256 (0x0001), HKDF-SHA384 (0x0002), and
HKDF-SHA512 (0x0003). The known AEADs are AES-128-GCM (0x0001), AES-256-GCM
(0x0002), ChaCha20Poly1305 (0x0003), and the special *export-only* AEAD
(0xFFFF), which produces contexts that cannot seal or open messages but can
still export secrets.

.. cpp:enum-class:: HPKE::KEM_Code : uint16_t

   The known KEM codepoints: ``DHKEM_P256``, ``DHKEM_P384``, ``DHKEM_P521``,
   ``DHKEM_X25519``, and ``DHKEM_X448``, plus ``ML_KEM_512``, ``ML_KEM_768``,
   ``ML_KEM_1024``, ``MLKEM768_P256``, ``MLKEM1024_P384``, and
   ``MLKEM768_X25519`` for the :ref:`post-quantum KEMs <hpke_pq_kems>`.

.. cpp:enum-class:: HPKE::KDF_Code : uint16_t

   The known KDF codepoints: ``HKDF_SHA256``, ``HKDF_SHA384``, and
   ``HKDF_SHA512``.

.. cpp:enum-class:: HPKE::AEAD_Code : uint16_t

   The known AEAD codepoints: ``AES_128_GCM``, ``AES_256_GCM``,
   ``ChaCha20Poly1305``, and ``ExportOnly``.

.. cpp:class:: HPKE::KEM_Id

   Identifies a KEM. Implicitly constructible from a
   :cpp:enum:`HPKE::KEM_Code` enumerator or from a raw ``uint16_t`` read off
   the wire. The enumerators are also reachable through this type, as in
   ``KEM_Id::DHKEM_X25519``.

   .. cpp:function:: uint16_t wire_code() const

      The IANA codepoint.

   .. cpp:function:: bool is_known() const

      True if this codepoint is known to this version of the library.

   .. cpp:function:: bool is_available() const

      True if the algorithms this KEM requires are available in this build.

   .. cpp:function:: bool is_dhkem() const

      True for the Diffie-Hellman based KEMs of RFC 9180.

   .. cpp:function:: bool is_ml_kem() const

      True for ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

   .. cpp:function:: bool is_pq_hybrid() const

      True for the KEMs which combine ML-KEM with an elliptic curve group:
      MLKEM768-P256, MLKEM1024-P384, and MLKEM768-X25519.

   .. cpp:function:: bool supports_auth_modes() const

      True if this KEM supports the *auth* and *auth_psk* modes; only the
      DH-based KEMs do.

   .. cpp:function:: size_t shared_secret_length() const
   .. cpp:function:: size_t encapsulation_length() const
   .. cpp:function:: size_t public_key_length() const
   .. cpp:function:: size_t private_key_length() const

      The RFC 9180 constants *Nsecret*, *Nenc*, *Npk*, and *Nsk*. These are
      usable for any known codepoint, even one that is not available in the
      build (as needed, for instance, to emit an ECH GREASE extension of
      plausible size). They throw ``Invalid_State`` for unknown codepoints.

   .. cpp:function:: std::optional<std::string> to_string() const

      A human readable name, or ``nullopt`` for unknown codepoints.

.. cpp:class:: HPKE::KDF_Id

   Identifies a KDF; the same shape as :cpp:class:`HPKE::KEM_Id`, plus

   .. cpp:function:: size_t output_length() const

      The KDF output length *Nh*.

.. cpp:class:: HPKE::AEAD_Id

   Identifies an AEAD; the same shape as :cpp:class:`HPKE::KEM_Id`, plus

   .. cpp:function:: bool is_export_only() const

      True for the export-only AEAD (0xFFFF).

   .. cpp:function:: size_t key_length() const
   .. cpp:function:: size_t nonce_length() const
   .. cpp:function:: size_t tag_length() const

      The AEAD constants *Nk*, *Nn*, and *Nt*. These throw ``Invalid_State``
      for the export-only AEAD, for which they are undefined.

.. cpp:class:: HPKE::Suite

   The ciphersuite triple.

   .. cpp:function:: Suite(KEM_Id kem, KDF_Id kdf, AEAD_Id aead)

   .. cpp:function:: KEM_Id kem() const
   .. cpp:function:: KDF_Id kdf() const
   .. cpp:function:: AEAD_Id aead() const

   .. cpp:function:: bool is_known() const
   .. cpp:function:: bool is_available() const
   .. cpp:function:: bool is_export_only() const

   .. cpp:function:: size_t ciphertext_overhead() const

      The number of bytes :cpp:func:`HPKE::Sender_Context::seal` adds to a
      plaintext (the AEAD tag length). Throws ``Invalid_State`` for an
      export-only suite, which cannot seal.

Keys
----------------------------------------

HPKE keys are represented by dedicated types, unrelated by inheritance to
each other and to ``Botan::Public_Key``/``Botan::Private_Key``. Both are
cheaply copyable value types.

A key is checked against a specific KEM when it is created: its algorithm
(and, for the NIST curves, its group) must match the KEM, and a key
deserialized from the wire must be well formed, which for the NIST curves
includes being a point on the curve. Private keys are fully validated at
this point. For public keys one check is deferred: RFC 9180 specifies the
rejection of low order X25519/X448 points in terms of the Diffie-Hellman
output, so such a key can be constructed, and is rejected (with
``Invalid_Argument``) by any context setup that uses it. Holding an
``HPKE::Public_Key`` therefore guarantees that the key matches its KEM and
is well formed, but not that an untrusted peer's key will be accepted when
a context is set up.

.. cpp:class:: HPKE::Public_Key

   .. cpp:function:: static Public_Key deserialize(KEM_Id kem, std::span<const uint8_t> bytes)

      *DeserializePublicKey* from RFC 9180. Accepts exactly the wire format
      the KEM defines (raw bytes for X25519/X448, an uncompressed SEC1
      point for the NIST curves), throwing ``Decoding_Error`` if the length
      or encoding is wrong or a NIST curve point is not on the curve. See
      :ref:`hpke_pq_kems` for the checks applied to the keys of those KEMs.

   .. cpp:function:: static Public_Key from_key(KEM_Id kem, std::unique_ptr<Botan::Public_Key> key)

      Adopts an existing key, for example one taken from an X.509 structure.
      For the NIST curves both ECDH and ECDSA keys are accepted, since keys
      carrying the ``id-ecPublicKey`` algorithm identifier load as ECDSA
      keys; an ECDSA key is converted, so ``underlying()`` always returns an
      ECDH key. Keys of other EC algorithms (SM2, ECGDSA, and so on) are
      rejected. Throws ``Invalid_Argument`` unless the key's algorithm (and,
      for the NIST curves, its group) matches the KEM.

   .. cpp:function:: KEM_Id kem() const

   .. cpp:function:: std::vector<uint8_t> serialize() const

      *SerializePublicKey* from RFC 9180; the format used on the wire by
      ECH, MLS, etc.

   .. cpp:function:: const Botan::Public_Key& underlying() const

      Access to the wrapped key, for example for encoding as an X.509
      ``SubjectPublicKeyInfo``. For the NIST curves this is an ECDH key,
      whose encoding uses the ``id-ecDH`` algorithm identifier.

.. cpp:class:: HPKE::Private_Key

   .. cpp:function:: static Private_Key generate(KEM_Id kem, RandomNumberGenerator& rng)

   .. cpp:function:: static Private_Key derive(KEM_Id kem, std::span<const uint8_t> ikm)

      *DeriveKeyPair* from RFC 9180: deterministically derives a key pair
      from full-entropy secret keying material of at least *Nsk* bytes. As
      an exception, DHKEM(P-521) accepts 64 bytes, because MLS (:rfc:`9420`)
      derives the P-521 node keys of its ratchet tree from 64-byte secrets.
      The post-quantum KEMs require at least 32 bytes.

   .. cpp:function:: static Private_Key deserialize(KEM_Id kem, std::span<const uint8_t> bytes)

      *DeserializePrivateKey* from RFC 9180: accepts *Nsk* raw bytes. The
      scalar is range-checked for the NIST curves, and clamped (:rfc:`7748`
      section 5) for X25519 and X448. For the post-quantum KEMs the bytes
      are the seed.

   .. cpp:function:: static Private_Key from_key(KEM_Id kem, std::unique_ptr<Botan::Private_Key> key)

      Adopts an existing key, for example one loaded from PKCS #8, with the
      same rules as :cpp:func:`HPKE::Public_Key::from_key`: ECDSA keys on
      the NIST curves are accepted and converted to ECDH.

   .. cpp:function:: KEM_Id kem() const

   .. cpp:function:: Public_Key public_key() const

      The corresponding public key.

   .. cpp:function:: secure_vector<uint8_t> serialize() const

      *SerializePrivateKey* from RFC 9180, suitable for persisting eg an ECH
      server key. For X25519 and X448 the output is clamped, as the RFC
      requires. PKCS #8 encoding remains available via ``underlying()``,
      except for the hybrid post-quantum KEMs.

   .. cpp:function:: const Botan::Private_Key& underlying() const

.. _hpke_pq_kems:

Post-Quantum KEMs (Experimental)
----------------------------------------

.. warning::

   These KEMs are experimental. They are provided by the module ``hpke_pq``,
   which is not part of a default build; configure with
   ``--enable-modules=hpke_pq`` or ``--enable-experimental-features`` to
   build it. They are implemented as specified by draft-ietf-hpke-pq-05,
   which is not yet a published RFC. If the specification changes, the
   implementation will be changed to follow it, even where that is
   incompatible with the current behavior, until the module is marked
   stable.

The ``hpke_pq`` module provides the KEMs of `draft-ietf-hpke-pq
<https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/>`_, which protect
against an adversary who records traffic now in order to decrypt it using
a quantum computer later. It requires the ``ml_kem`` module, and
MLKEM768-X25519 additionally requires ``x25519``. C++ code can detect the
module at compile time by testing for the macro ``BOTAN_HAS_HPKE_PQ``. In a
build without the module the codepoints are still known, so that for example
their lengths can be queried, but :cpp:func:`HPKE::KEM_Id::is_available`
returns false for them and using one throws ``Not_Implemented``.

There are two kinds:

* ML-KEM-512, ML-KEM-768, and ML-KEM-1024 use ML-KEM (FIPS 203) directly.

* MLKEM768-P256, MLKEM1024-P384, and MLKEM768-X25519 are hybrids which
  combine ML-KEM with an elliptic curve Diffie-Hellman exchange, and remain
  secure as long as either of the two does. These are the KEMs defined in
  draft-irtf-cfrg-concrete-hybrid-kems-03; MLKEM768-X25519 is also known as
  X-Wing.

They are used through exactly the same interface as the other KEMs, with
the following differences:

* Public keys and encapsulations are much larger, between 768 and 1665
  bytes; see :cpp:func:`HPKE::KEM_Id::public_key_length` and
  :cpp:func:`HPKE::KEM_Id::encapsulation_length`.

* The *auth* and *auth_psk* modes are not available. The *psk* mode is.

* The serialized private key is a seed, of 64 bytes for ML-KEM and 32 bytes
  for the hybrids, from which the actual key material is expanded.

* A modified ML-KEM ciphertext is rejected *implicitly*. Setting up a
  recipient context with a corrupted encapsulation normally succeeds, and
  results in a context whose keys are unrelated to the sender's, so that the
  first ``open`` fails. An error is reported at setup only if the
  encapsulation has the wrong length, or (for a hybrid) its elliptic curve
  component is invalid.

* For ML-KEM, :cpp:func:`HPKE::Private_Key::from_key` and
  :cpp:func:`HPKE::Public_Key::from_key` accept an ML-KEM key of the matching
  parameter set, and ``underlying()`` returns such a key, so keys can be
  stored as PKCS #8 or X.509 structures. A private key that was loaded from
  the expanded encoding of FIPS 203, which does not include the seed, can be
  used to set up contexts, but :cpp:func:`HPKE::Private_Key::serialize`
  throws ``Invalid_State`` for it.

* The hybrid KEMs have no standalone key type in the library. A key is
  created using ``generate``, ``derive``, or ``deserialize``, and the key
  returned by ``underlying()`` supports only the raw encodings; there is no
  PKCS #8 or X.509 encoding of these keys.

Deserializing a public key performs the encapsulation key check of FIPS 203,
and for MLKEM768-P256 and MLKEM1024-P384 checks that the elliptic curve
point uses the uncompressed encoding and is on the curve. As with the DHKEM
it is paired with, a low order X25519 point in a MLKEM768-X25519 public key
or encapsulation is detected (causing ``Invalid_Argument``) only when a
context is set up.

The SHAKE and TurboSHAKE based KDFs which draft-ietf-hpke-pq also defines
are not implemented.

Pre-shared keys
----------------------------------------

.. cpp:class:: HPKE::PSK

   Holds the pre-shared key and its identity for the *psk* and *auth_psk*
   modes.

   .. cpp:function:: PSK(std::span<const uint8_t> psk, std::span<const uint8_t> psk_id)

      Both values must be non-empty, and (following the recommendation of
      RFC 9180 section 9.5) the PSK must be at least 32 bytes; violating
      either throws ``Invalid_Argument``. Section 9.5 further recommends a
      PSK of at least *Nh* bytes, the output length of the suite's KDF (32,
      48, or 64 bytes for the KDFs of RFC 9180 section 7.2); this is not
      enforced, since a PSK is not bound to a suite when constructed. Note
      that the PSK mechanism is *not* a substitute for password
      authentication: the PSK must be a full-entropy cryptographic key, as
      HPKE does not defend against offline dictionary attacks on it.

Encryption contexts
----------------------------------------

Contexts are created by static factories that correspond one to one with
the RFC 9180 setup functions (``SetupBaseS``, ``SetupPSKR``, and so on).
All of the factories throw ``Invalid_Argument`` if a provided key does not
match the suite's KEM, if a peer's key is a low order X25519/X448 point, or
if an authenticated mode is requested for a KEM that does not support it,
and throw ``Not_Implemented`` or ``Lookup_Error`` if the suite is not
available in the build. Both context types are movable but not copyable.

.. cpp:enum-class:: HPKE::Mode : uint8_t

   The mode of a context: ``Base``, ``PSK``, ``Auth``, or ``AuthPSK``, with
   the values being the RFC 9180 codepoints.

.. cpp:class:: HPKE::Sender_Context

   .. cpp:function:: static Sender_Context setup_base(const Suite& suite, \
         const Public_Key& recipient_key, RandomNumberGenerator& rng, \
         std::span<const uint8_t> info = {})

   .. cpp:function:: static Sender_Context setup_psk(const Suite& suite, \
         const Public_Key& recipient_key, RandomNumberGenerator& rng, \
         const PSK& psk, std::span<const uint8_t> info = {})

   .. cpp:function:: static Sender_Context setup_auth(const Suite& suite, \
         const Public_Key& recipient_key, const Private_Key& sender_identity_key, \
         RandomNumberGenerator& rng, std::span<const uint8_t> info = {})

   .. cpp:function:: static Sender_Context setup_auth_psk(const Suite& suite, \
         const Public_Key& recipient_key, const Private_Key& sender_identity_key, \
         RandomNumberGenerator& rng, const PSK& psk, std::span<const uint8_t> info = {})

      Encapsulate a fresh shared secret to ``recipient_key`` and derive an
      encryption context bound to ``info``.

   .. cpp:function:: const std::vector<uint8_t>& encapsulated_key() const

      The KEM encapsulation (*enc*), which must be transmitted to the
      recipient.

   .. cpp:function:: std::vector<uint8_t> seal(std::span<const uint8_t> aad, \
         std::span<const uint8_t> ptext)

      Encrypt a message using the next sequence number. The additional data
      ``aad`` is authenticated but not encrypted, and the recipient must
      present the same value. Throws ``Invalid_State`` for an export-only
      suite.

   .. cpp:function:: secure_vector<uint8_t> export_secret( \
         std::span<const uint8_t> exporter_context, size_t length) const

      The RFC 9180 secret export interface. Derives a secret bound to this
      context and to ``exporter_context``; the recipient's context derives
      the same value. ``length`` may be at most 255 times the KDF output
      length.

   .. cpp:function:: uint64_t next_sequence() const

      The sequence number the next call to ``seal`` will use.

   .. cpp:function:: Mode mode() const
   .. cpp:function:: Suite suite() const

.. cpp:class:: HPKE::Recipient_Context

   .. cpp:function:: static Recipient_Context setup_base(const Suite& suite, \
         const Private_Key& recipient_key, std::span<const uint8_t> enc, \
         RandomNumberGenerator& rng, std::span<const uint8_t> info = {})

   .. cpp:function:: static Recipient_Context setup_psk(const Suite& suite, \
         const Private_Key& recipient_key, std::span<const uint8_t> enc, \
         RandomNumberGenerator& rng, const PSK& psk, std::span<const uint8_t> info = {})

   .. cpp:function:: static Recipient_Context setup_auth(const Suite& suite, \
         const Private_Key& recipient_key, std::span<const uint8_t> enc, \
         const Public_Key& sender_identity_key, RandomNumberGenerator& rng, \
         std::span<const uint8_t> info = {})

   .. cpp:function:: static Recipient_Context setup_auth_psk(const Suite& suite, \
         const Private_Key& recipient_key, std::span<const uint8_t> enc, \
         const Public_Key& sender_identity_key, RandomNumberGenerator& rng, \
         const PSK& psk, std::span<const uint8_t> info = {})

      Decapsulate ``enc`` with ``recipient_key`` and derive the matching
      decryption context. Throws ``Decoding_Error`` if ``enc`` is malformed
      (wrong length or encoding, or not a point on the curve), and
      ``Invalid_Argument`` if it is a low order X25519/X448 point. The RNG
      is required by the underlying decapsulation operations, eg for
      blinding.

   .. cpp:function:: secure_vector<uint8_t> open(std::span<const uint8_t> aad, \
         std::span<const uint8_t> ctext)

      Decrypt a message using the next sequence number. Decryption fails
      in ``Invalid_Authentication_Tag`` if the ciphertext is truncated or
      fails authentication. A failed open does not consume the sequence
      number. Export-only contexts and exhausted sequence numbers cause
      ``Invalid_State``.

   .. cpp:function:: secure_vector<uint8_t> open_at_sequence(uint64_t seq, \
         std::span<const uint8_t> aad, std::span<const uint8_t> ctext)

      Decrypt the message with an explicit sequence number, without reading
      or modifying the counter used by ``open``. This supports out-of-order
      transports and stateless processing; for example, an ECH server
      handling a retried ClientHello after a stateless HelloRetryRequest
      recreates the context by decapsulating the (unchanged) ``enc`` again
      and opens the second inner ClientHello at sequence number 1.

      No sealing equivalent is provided, since explicitly choosing the
      sequence number on the sending side invites catastrophic nonce reuse.

   .. cpp:function:: secure_vector<uint8_t> export_secret( \
         std::span<const uint8_t> exporter_context, size_t length) const

   .. cpp:function:: uint64_t next_sequence() const
   .. cpp:function:: Mode mode() const
   .. cpp:function:: Suite suite() const

Code Example
----------------------------------------

The example below encrypts messages to a recipient known only by its
published public key, then uses the secret export interface.

.. literalinclude:: /../src/examples/hpke.cpp
   :language: cpp

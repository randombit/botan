Cryptographic Message Syntax (CMS)
====================================

.. versionadded:: 3.15.0

Botan implements a subset of the Cryptographic Message Syntax (CMS, RFC
5652), the format underlying S/MIME: the enveloped-data and
authenticated-enveloped-data content types for encrypting a message to
one or more certificate holders, and the signed-data content type for
creating and verifying signatures.

All functionality is available via ``botan/cms.h`` in the ``Botan::CMS``
namespace, and through the ``cms_encrypt``, ``cms_decrypt``,
``cms_sign`` and ``cms_verify`` CLI commands.

Algorithm Support
-------------------

.. list-table::
   :header-rows: 1

   * - Element
     - Supported
   * - Content encryption
     - AES-128/GCM, AES-256/GCM (AuthEnvelopedData, RFC 5083/5084);
       AES-128/CBC, AES-256/CBC (EnvelopedData)
   * - Key transport recipients (ktri)
     - RSA with OAEP (creation uses SHA-256) or PKCS#1 v1.5
   * - KEM recipients (RFC 9629)
     - ML-KEM-512/768/1024 (RFC 9936), HKDF (SHA-256 on creation;
       SHA-256/384/512 accepted), AES key wrap
   * - Signature creation and verification
     - RSA (PKCS#1 v1.5), ECDSA, Ed25519, ML-DSA
   * - Digests on verification
     - SHA-256, SHA-384, SHA-512, SHA-3; anything else (notably MD5 and
       SHA-1) is rejected
   * - Encapsulated content type
     - id-data only

Not supported: key agreement (ECDH) recipients, password and previously
distributed KEK recipients, OriginatorInfo processing, CompressedData,
DigestedData, EncryptedData, countersignatures, timestamps, and content
types other than id-data. Unsupported RecipientInfo entries in a
received message are skipped, and decryption fails only if no supported
recipient matches. CRLs embedded in SignedData are tolerated but never
processed or produced.

Input requirements
--------------------

Received messages may use BER encoding, including the streaming
indefinite-length form with fragmented (constructed) OCTET STRING
content that ``openssl cms`` emits by default. Signed attributes must
be DER encoded, as RFC 5652 requires. All messages produced by Botan
use definite-length DER. Messages are processed entirely in memory in
both directions; there is no streaming API.

Encrypting and Decrypting
---------------------------

.. cpp:class:: Botan::CMS::Enveloped_Data_Builder

   .. cpp:function:: Enveloped_Data_Builder& add_ktri_recipient(const X509_Certificate& cert, \
         std::string_view padding = "OAEP(SHA-256)")

      Add an RSA key transport recipient. The padding is either
      ``"OAEP(SHA-256)"`` (the default) or ``"PKCS1v15"``.

   .. cpp:function:: Enveloped_Data_Builder& add_kem_recipient(const X509_Certificate& cert)

      Add an RFC 9629 KEM recipient; the certificate must carry an
      ML-KEM public key. The content encryption key is wrapped with
      AES-256 key wrap under a key derived with HKDF-SHA-256.

   .. cpp:function:: Enveloped_Data_Builder& set_content_encryption(std::string_view algo)

      Select the content encryption algorithm: ``"AES-256/GCM"`` (the
      default) or ``"AES-128/GCM"`` produce AuthEnvelopedData;
      ``"AES-128/CBC"`` and ``"AES-256/CBC"`` produce EnvelopedData.

   .. cpp:function:: std::vector<uint8_t> build(std::span<const uint8_t> content, \
         RandomNumberGenerator& rng) const

      Encrypt ``content`` for all configured recipients and return a
      DER-encoded ContentInfo.

.. cpp:function:: secure_vector<uint8_t> Botan::CMS::decrypt(std::span<const uint8_t> content_info, \
      const Private_Key& key, const X509_Certificate& cert, RandomNumberGenerator& rng)

   Decrypt a BER-encoded ContentInfo holding EnvelopedData or
   AuthEnvelopedData. The recipient entry is located by matching
   ``cert``. Throws ``Decoding_Error`` on malformed input,
   ``Invalid_Argument`` if no supported RecipientInfo matches ``cert``,
   and ``CMS::Decryption_Error`` if recovery of the content encryption
   key or the content fails.

.. warning::

   EnvelopedData with CBC content encryption provides no integrity
   protection: anyone can undetectably manipulate the ciphertext, and
   decryption of manipulated messages can be abused as a padding
   oracle. This is inherent to the format. Prefer AuthEnvelopedData
   (AES-GCM), and treat CBC support primarily as a compatibility
   feature for decrypting messages from legacy peers.

Signing and Verifying
-----------------------

.. cpp:class:: Botan::CMS::Signed_Data_Builder

   .. cpp:function:: Signed_Data_Builder& add_signer(const X509_Certificate& cert, \
         const Private_Key& key, std::string_view hash_fn = "SHA-256", \
         std::string_view padding = "")

      Add a signer. The key object must remain alive until ``sign`` is
      called. The default padding is chosen per key type with the same
      rules as X.509 certificate signing. For Ed25519 and ML-DSA the
      hash choice is ignored and SHA-512 is used for the
      message-digest attribute.

   .. cpp:function:: Signed_Data_Builder& include_certificate(const X509_Certificate& cert)

      Embed an additional certificate (for example the issuing CA) in
      the message. Signer certificates are always included.

   .. cpp:function:: Signed_Data_Builder& detached(bool is_detached)

      If set, the content itself is omitted from the message (an
      "external signature").

   .. cpp:function:: std::vector<uint8_t> sign(std::span<const uint8_t> content, \
         RandomNumberGenerator& rng) const

      Sign ``content`` and return a DER-encoded ContentInfo. Signed
      attributes (content-type, message-digest, signing-time, and
      CMSAlgorithmProtection) are always included.

.. cpp:function:: CMS::Signed_Data_Verification Botan::CMS::verify( \
      std::span<const uint8_t> content_info, \
      std::optional<std::span<const uint8_t>> detached_content, \
      Certificate_Store* trusted_roots, \
      std::chrono::system_clock::time_point validation_time)

   Verify all signatures of a BER-encoded ContentInfo holding
   SignedData. ``detached_content`` must be provided exactly when the
   message is detached. Verification is all-or-nothing: a failure of
   any signer throws ``CMS::Verification_Error``.

   If ``trusted_roots`` is non-null each signer certificate is
   additionally path-validated at ``validation_time``, and the result
   is available from ``path_result()``. Callers passing trust roots
   must check ``path_result()->successful_validation()``; a verified
   signature by itself only proves possession of the key matching the
   (possibly untrustworthy) embedded certificate.

.. cpp:class:: Botan::CMS::Signed_Data_Verification

   .. cpp:function:: const std::vector<X509_Certificate>& signers() const

      The certificates whose signatures verified, one per SignerInfo.

   .. cpp:function:: bool has_content() const

      True if the message carried its content, false for a detached
      signature. An attached message with empty content reports true.

   .. cpp:function:: const std::vector<uint8_t>& content() const

      The encapsulated content. Throws ``Invalid_State`` if
      ``has_content()`` is false.

   .. cpp:function:: const std::optional<Path_Validation_Result>& path_result() const

      Set only when ``trusted_roots`` was given to ``verify``.

Post-Quantum Usage
--------------------

For encryption, prefer AuthEnvelopedData with an ML-KEM recipient::

   Botan::CMS::Enveloped_Data_Builder builder;
   builder.add_kem_recipient(mlkem_cert);  // AES-256/GCM is the default
   auto msg = builder.build(plaintext, rng);

When an ML-KEM recipient certificate contains a ``keyUsage`` extension,
it must permit only ``keyEncipherment``, as required by RFC 9935.

For signatures, use an ML-DSA signer::

   Botan::CMS::Signed_Data_Builder builder;
   builder.add_signer(mldsa_cert, mldsa_key);
   auto msg = builder.sign(content, rng);

Both interoperate with openssl >= 3.5.

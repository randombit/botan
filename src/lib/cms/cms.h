/*
* Cryptographic Message Syntax (RFC 5652)
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CMS_H_
#define BOTAN_CMS_H_

#include <botan/asn1_obj.h>
#include <botan/exceptn.h>
#include <botan/pkix_types.h>
#include <botan/secmem.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>
#include <chrono>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace Botan {

class Private_Key;
class RandomNumberGenerator;
class Certificate_Store;

}  // namespace Botan

namespace Botan::CMS {

/**
* Thrown when recovery of the content encryption key or decryption of
* the content itself fails.
*/
class BOTAN_PUBLIC_API(3, 15) Decryption_Error final : public Exception {
   public:
      explicit Decryption_Error(std::string_view msg) : Exception("CMS decryption failed:", msg) {}

      ErrorType error_type() const noexcept override { return ErrorType::InvalidTag; }
};

/**
* Thrown when a SignedData signature does not verify, or when a signed
* attribute is inconsistent with the content.
*/
class BOTAN_PUBLIC_API(3, 15) Verification_Error final : public Exception {
   public:
      explicit Verification_Error(std::string_view msg) : Exception("CMS verification failed:", msg) {}

      ErrorType error_type() const noexcept override { return ErrorType::InvalidTag; }
};

/**
* RFC 5652 IssuerAndSerialNumber
*/
class BOTAN_PUBLIC_API(3, 15) IssuerAndSerialNumber final : public ASN1_Object {
   public:
      IssuerAndSerialNumber() = default;

      /**
      * Identify @p cert by its issuer DN and serial number
      */
      explicit IssuerAndSerialNumber(const X509_Certificate& cert);

      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;

      const X509_DN& issuer() const { return m_issuer; }

      const X509_Serial_Number& serial() const { return m_serial; }

      /**
      * Return true if this issuer/serial identifies @p cert
      */
      bool matches(const X509_Certificate& cert) const;

   private:
      X509_DN m_issuer;
      X509_Serial_Number m_serial;
};

/**
* RFC 5652 SignerIdentifier, also used as RecipientIdentifier: a CHOICE
* of IssuerAndSerialNumber or [0] SubjectKeyIdentifier
*/
class BOTAN_PUBLIC_API(3, 15) SignerIdentifier final : public ASN1_Object {
   public:
      SignerIdentifier() = default;

      /**
      * Identify @p cert using the issuerAndSerialNumber alternative
      */
      explicit SignerIdentifier(const X509_Certificate& cert);

      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;

      bool is_issuer_and_serial() const { return std::holds_alternative<IssuerAndSerialNumber>(m_id); }

      /**
      * Precondition: is_issuer_and_serial() is true
      */
      const IssuerAndSerialNumber& issuer_and_serial() const;

      /**
      * Precondition: is_issuer_and_serial() is false
      */
      const std::vector<uint8_t>& subject_key_id() const;

      /**
      * Return true if this identifier matches @p cert
      */
      bool matches(const X509_Certificate& cert) const;

   private:
      std::variant<IssuerAndSerialNumber, std::vector<uint8_t>> m_id;
};

/**
* Creates an EnvelopedData (RFC 5652) or AuthEnvelopedData (RFC 5083)
* message, depending on the chosen content encryption algorithm.
*/
class BOTAN_PUBLIC_API(3, 15) Enveloped_Data_Builder final {
   public:
      Enveloped_Data_Builder();
      ~Enveloped_Data_Builder();
      Enveloped_Data_Builder(const Enveloped_Data_Builder&) = delete;
      Enveloped_Data_Builder& operator=(const Enveloped_Data_Builder&) = delete;
      Enveloped_Data_Builder(Enveloped_Data_Builder&&) noexcept;
      Enveloped_Data_Builder& operator=(Enveloped_Data_Builder&&) noexcept;

      /**
      * Add an RSA key transport recipient; @p padding is "OAEP(SHA-256)"
      * (the default) or "PKCS1v15"
      */
      Enveloped_Data_Builder& add_ktri_recipient(const X509_Certificate& cert,
                                                 std::string_view padding = "OAEP(SHA-256)");

      /**
      * Add a KEM recipient (RFC 9629); the cert must carry an ML-KEM key.
      * The KDF is HKDF-SHA-256 and the key wrap is AES-256 key wrap.
      */
      Enveloped_Data_Builder& add_kem_recipient(const X509_Certificate& cert);

      /**
      * Set the content encryption algorithm: "AES-256/GCM" (the default)
      * or "AES-128/GCM" produce AuthEnvelopedData; "AES-128/CBC" or
      * "AES-256/CBC" produce EnvelopedData.
      */
      Enveloped_Data_Builder& set_content_encryption(std::string_view algo);

      /**
      * Encrypt @p content for the configured recipients.
      * @return a DER-encoded ContentInfo
      */
      std::vector<uint8_t> build(std::span<const uint8_t> content, RandomNumberGenerator& rng) const;

   private:
      struct Recipient;
      std::vector<Recipient> m_recipients;
      std::string m_content_enc_algo;
};

/**
* Decrypt a BER-encoded ContentInfo holding EnvelopedData or
* AuthEnvelopedData. The recipient is located by matching @p cert
* against each RecipientInfo (by IssuerAndSerialNumber or
* SubjectKeyIdentifier). Throws Decoding_Error on malformed input,
* Invalid_Argument if no RecipientInfo matches, Decryption_Error on
* CEK unwrap or content decryption failure.
*/
BOTAN_PUBLIC_API(3, 15)
secure_vector<uint8_t> decrypt(std::span<const uint8_t> content_info,
                               const Private_Key& key,
                               const X509_Certificate& cert,
                               RandomNumberGenerator& rng);

/**
* Creates a SignedData (RFC 5652) message, always with signed
* attributes (content-type, message-digest, signing-time, and
* CMSAlgorithmProtection).
*/
class BOTAN_PUBLIC_API(3, 15) Signed_Data_Builder final {
   public:
      Signed_Data_Builder();
      ~Signed_Data_Builder();
      Signed_Data_Builder(const Signed_Data_Builder&) = delete;
      Signed_Data_Builder& operator=(const Signed_Data_Builder&) = delete;
      Signed_Data_Builder(Signed_Data_Builder&&) noexcept;
      Signed_Data_Builder& operator=(Signed_Data_Builder&&) noexcept;

      /**
      * Add a signer. @p key must remain valid until sign() is called.
      * @p hash_fn e.g. "SHA-256"; the padding default is chosen per key
      * type using the same rules as X.509 certificate signing.
      */
      Signed_Data_Builder& add_signer(const X509_Certificate& cert,
                                      const Private_Key& key,
                                      std::string_view hash_fn = "SHA-256",
                                      std::string_view padding = "");

      /**
      * Embed an additional certificate (signer certs are always included)
      */
      Signed_Data_Builder& include_certificate(const X509_Certificate& cert);

      /**
      * If set, the eContent is omitted from the message ("external signature")
      */
      Signed_Data_Builder& detached(bool is_detached);

      /**
      * Sign @p content
      * @return a DER-encoded ContentInfo
      */
      std::vector<uint8_t> sign(std::span<const uint8_t> content, RandomNumberGenerator& rng) const;

   private:
      struct Signer;
      std::vector<Signer> m_signers;
      std::vector<X509_Certificate> m_certs;
      bool m_detached = false;
};

/**
* The result of verifying a SignedData message
*/
class BOTAN_PUBLIC_API(3, 15) Signed_Data_Verification final {
   public:
      Signed_Data_Verification(std::vector<X509_Certificate> signers,
                               std::optional<std::vector<uint8_t>> content,
                               std::optional<Path_Validation_Result> path_result);

      /** Certs whose signatures verified */
      const std::vector<X509_Certificate>& signers() const { return m_signers; }

      /**
      * True if the message carried its content, false if it was a
      * detached signature
      */
      bool has_content() const { return m_content.has_value(); }

      /**
      * The encapsulated content, which may be empty.
      * Precondition: has_content() is true
      */
      const std::vector<uint8_t>& content() const;

      /**
      * Set if trusted roots were given to verify(). Callers must check
      * that the result indicates a successful validation.
      */
      const std::optional<Path_Validation_Result>& path_result() const { return m_path_result; }

   private:
      std::vector<X509_Certificate> m_signers;
      std::optional<std::vector<uint8_t>> m_content;
      std::optional<Path_Validation_Result> m_path_result;
};

/**
* Verify all SignerInfos of a BER-encoded ContentInfo holding
* SignedData. @p detached_content must be provided iff the message is
* detached. If @p trusted_roots is non-null, each signer certificate is
* additionally path-validated; the caller must inspect the returned
* path_result(). Throws on structural errors; signature verification
* failure of any signer throws.
*/
BOTAN_PUBLIC_API(3, 15)
Signed_Data_Verification verify(std::span<const uint8_t> content_info,
                                std::optional<std::span<const uint8_t>> detached_content,
                                Certificate_Store* trusted_roots,
                                std::chrono::system_clock::time_point validation_time);

}  // namespace Botan::CMS

#endif

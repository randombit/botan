/*
* CMS SignedData
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cms.h>

#include <botan/asn1_time.h>
#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/certstor.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/pubkey.h>
#include <botan/x509_obj.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>
#include <botan/internal/cms_helpers.h>
#include <botan/internal/fmt.h>

#include <algorithm>

namespace Botan::CMS {

namespace {

bool approved_digest(std::string_view name) {
   return name == "SHA-256" || name == "SHA-384" || name == "SHA-512" || name == "SHA-3(224)" || name == "SHA-3(256)" ||
          name == "SHA-3(384)" || name == "SHA-3(512)";
}

void check_signature_algo_allowed(const AlgorithmIdentifier& sig_alg) {
   const std::string name = sig_alg.oid().human_name_or_empty();

   if(name == "Ed25519" || name == "ML-DSA-4x4" || name == "ML-DSA-6x5" || name == "ML-DSA-8x7") {
      if(!sig_alg.parameters_are_empty()) {
         throw Decoding_Error(fmt("CMS {} signature algorithm parameters must be absent", name));
      }
      return;
   }

   /*
   * RFC 3370 3.2: "The rsaEncryption algorithm identifier is used to
   * identify RSA (PKCS #1 v1.5) signature values regardless of the
   * message digest algorithm employed."
   */
   if(name == "RSA") {
      if(!sig_alg.parameters_are_null_or_empty()) {
         throw Decoding_Error("CMS rsaEncryption signature algorithm has unexpected parameters");
      }
      return;
   }

   // The remaining acceptable names have the form ALGO/PADDING(HASH)
   // or ALGO/HASH, with HASH possibly containing parens (SHA-3)
   const auto slash = name.find('/');
   if(slash != std::string::npos) {
      const std::string algo = name.substr(0, slash);
      const std::string padding = name.substr(slash + 1);

      if(algo == "ECDSA" && approved_digest(padding) && sig_alg.parameters_are_empty()) {
         return;
      }
      if(algo == "RSA" && padding.starts_with("PKCS1v15(") && padding.ends_with(')')) {
         const std::string hash = padding.substr(9, padding.size() - 10);
         if(approved_digest(hash) && sig_alg.parameters_are_null_or_empty()) {
            return;
         }
      }
   }

   throw Decoding_Error(fmt("Signature algorithm {} is not acceptable for CMS", sig_alg.oid()));
}

std::string approved_digest_algo(const AlgorithmIdentifier& digest_alg) {
   /*
   * RFC 5754 2: "Implementations MUST accept SHA2 AlgorithmIdentifiers
   * with absent parameters. Implementations MUST accept SHA2
   * AlgorithmIdentifiers with NULL parameters."
   */
   if(!digest_alg.parameters_are_null_or_empty()) {
      throw Decoding_Error("CMS digest AlgorithmIdentifier has unexpected parameters");
   }
   const std::string name = digest_alg.oid().human_name_or_empty();
   if(!approved_digest(name)) {
      throw Decoding_Error(fmt("Digest algorithm {} is not acceptable for CMS", digest_alg.oid()));
   }
   return name;
}

bool is_ml_dsa(std::string_view signature_algo) {
   return signature_algo == "ML-DSA-4x4" || signature_algo == "ML-DSA-6x5" || signature_algo == "ML-DSA-8x7";
}

bool signature_digest_matches(const AlgorithmIdentifier& sig_alg, std::string_view digest) {
   const std::string name = sig_alg.oid().human_name_or_empty();

   if(name == "RSA") {
      return approved_digest(digest);
   }
   if(name == "Ed25519") {
      return digest == "SHA-512";
   }
   if(name == "ML-DSA-4x4") {
      return digest == "SHA-256" || digest == "SHA-384" || digest == "SHA-512" || digest == "SHA-3(256)" ||
             digest == "SHA-3(384)" || digest == "SHA-3(512)";
   }
   if(name == "ML-DSA-6x5") {
      return digest == "SHA-384" || digest == "SHA-512" || digest == "SHA-3(384)" || digest == "SHA-3(512)";
   }
   if(name == "ML-DSA-8x7") {
      return digest == "SHA-512" || digest == "SHA-3(512)";
   }

   const auto slash = name.find('/');
   if(slash == std::string::npos) {
      return false;
   }

   const std::string padding = name.substr(slash + 1);
   if(name.starts_with("ECDSA/")) {
      return padding == digest;
   }
   if(name.starts_with("RSA/PKCS1v15(") && padding.ends_with(')')) {
      const std::string signature_digest = padding.substr(9, padding.size() - 10);
      return signature_digest == digest;
   }
   return false;
}

bool algorithm_identifiers_match(const AlgorithmIdentifier& lhs, const AlgorithmIdentifier& rhs) {
   return lhs.oid() == rhs.oid() && (lhs.parameters() == rhs.parameters() ||
                                     (lhs.parameters_are_null_or_empty() && rhs.parameters_are_null_or_empty()));
}

/*
* The digest placed in the digestAlgorithm field and used for the
* message-digest attribute. RFC 8419 3.1: "the digestAlgorithm MUST be
* id-sha512"; RFC 9882 3.3 requires SHA-512 support for ML-DSA and
* recommends it for interoperability.
*/
std::string digest_for_signer(const Private_Key& key, std::string_view hash_fn) {
   const std::string algo = key.algo_name();
   if(algo == "Ed25519" || algo == "ML-DSA") {
      return "SHA-512";
   }
   return std::string(hash_fn);
}

struct SignerInfoData {
      SignerIdentifier sid;
      AlgorithmIdentifier digest_alg;
      std::optional<std::vector<uint8_t>> signed_attrs_set;  // re-tagged as SET OF
      AlgorithmIdentifier sig_alg;
      std::vector<uint8_t> signature;
};

SignerInfoData decode_signer_info(const BER_Object& obj) {
   if(!obj.is_a(ASN1_Type::Sequence, ASN1_Class::Constructed)) {
      throw Decoding_Error("CMS SignerInfo is not a SEQUENCE");
   }

   SignerInfoData si;
   size_t version = 0;

   BER_Decoder dec(obj, BER_Decoder::Limits::BER());
   dec.decode(version).decode(si.sid).decode(si.digest_alg);

   if(dec.peek_next_object().is_a(ASN1_Type(0), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      si.signed_attrs_set = attrs_as_set_encoding(dec.get_next_object());
   }

   dec.decode(si.sig_alg).decode(si.signature, ASN1_Type::OctetString);

   // unsignedAttrs are not covered by the signature; skip them
   if(dec.peek_next_object().is_a(ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      dec.get_next_object();
   }
   dec.verify_end();

   /*
   * RFC 5652 5.3: "If the SignerIdentifier is the CHOICE
   * issuerAndSerialNumber, then the version MUST be 1. If the
   * SignerIdentifier is subjectKeyIdentifier, then the version MUST
   * be 3."
   */
   const size_t expected_version = si.sid.is_issuer_and_serial() ? 1 : 3;
   if(version != expected_version) {
      throw Decoding_Error("CMS SignerInfo has invalid version");
   }

   return si;
}

/*
* Parse a SET OF Attribute from its universal SET encoding, and locate
* the single value of the given attribute type. Enforces that the
* attribute appears exactly once with exactly one value.
*/
std::vector<uint8_t> require_single_attr_value(const std::vector<Attribute>& attrs, const OID& type) {
   std::optional<std::vector<uint8_t>> value;
   for(const auto& attr : attrs) {
      if(attr.oid() != type) {
         continue;
      }
      if(value) {
         throw Decoding_Error(fmt("CMS signedAttrs contains multiple {} attributes", type));
      }
      value = attr.parameters();
   }
   if(!value) {
      throw Decoding_Error(fmt("CMS signedAttrs is missing the {} attribute", type));
   }
   return *value;
}

void check_signed_attrs(std::span<const uint8_t> attrs_set,
                        const OID& econtent_type,
                        std::span<const uint8_t> content_digest,
                        const AlgorithmIdentifier& digest_alg,
                        const AlgorithmIdentifier& sig_alg) {
   std::vector<Attribute> attrs;
   // RFC 5652 5.3: "SignedAttributes MUST be DER encoded, even if the
   // rest of the structure is BER encoded."
   BER_Decoder dec(attrs_set, BER_Decoder::Limits::DER());
   dec.decode_list(attrs, ASN1_Type::Set, ASN1_Class::Universal).verify_end();
   if(attrs.empty()) {
      throw Decoding_Error("CMS signedAttrs is present but empty");
   }

   const auto content_type_val = require_single_attr_value(attrs, OID::from_string("PKCS9.ContentType"));
   OID content_type;
   BER_Decoder(content_type_val, BER_Decoder::Limits::DER()).decode(content_type).verify_end();
   /*
   * RFC 5652 11.1: "The content-type attribute value MUST match the
   * encapContentInfo eContentType value in the signed-data"
   */
   if(content_type != econtent_type) {
      throw Verification_Error("content-type attribute does not match eContentType");
   }

   const auto digest_val = require_single_attr_value(attrs, OID::from_string("PKCS9.MessageDigest"));
   std::vector<uint8_t> message_digest;
   BER_Decoder(digest_val, BER_Decoder::Limits::DER()).decode(message_digest, ASN1_Type::OctetString).verify_end();
   /*
   * RFC 5652 5.6: "For the signature to be valid, the message digest
   * value calculated by the recipient MUST be the same as the value of
   * the messageDigest attribute included in the signedAttributes of
   * the SignedData signerInfo."
   */
   if(!std::ranges::equal(message_digest, content_digest)) {
      throw Verification_Error("message-digest attribute does not match the content");
   }

   const OID algorithm_protection_oid = OID::from_string("PKCS9.CMSAlgorithmProtection");
   std::optional<std::vector<uint8_t>> algorithm_protection;
   for(const auto& attr : attrs) {
      if(attr.oid() == algorithm_protection_oid) {
         if(algorithm_protection) {
            throw Decoding_Error("CMS signedAttrs contains multiple CMSAlgorithmProtection attributes");
         }
         algorithm_protection = attr.parameters();
      }
   }

   if(algorithm_protection) {
      AlgorithmIdentifier protected_digest_alg;
      AlgorithmIdentifier protected_sig_alg;
      BER_Decoder protection(*algorithm_protection, BER_Decoder::Limits::DER());
      BER_Decoder seq = protection.start_sequence();
      seq.decode(protected_digest_alg);
      const BER_Object protected_sig_obj = seq.get_next_object();
      if(!protected_sig_obj.is_a(ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         throw Decoding_Error("CMSAlgorithmProtection is missing signatureAlgorithm");
      }
      std::vector<uint8_t> protected_sig_encoding;
      DER_Encoder(protected_sig_encoding)
         .add_object(ASN1_Type::Sequence, ASN1_Class::Universal | ASN1_Class::Constructed, protected_sig_obj.data());
      BER_Decoder(protected_sig_encoding, BER_Decoder::Limits::DER()).decode(protected_sig_alg).verify_end();
      seq.end_cons();
      protection.verify_end();

      approved_digest_algo(protected_digest_alg);
      check_signature_algo_allowed(protected_sig_alg);
      if(!algorithm_identifiers_match(protected_digest_alg, digest_alg) ||
         !algorithm_identifiers_match(protected_sig_alg, sig_alg)) {
         throw Verification_Error("CMSAlgorithmProtection does not match SignerInfo algorithms");
      }
   }
}

struct SignedMessage {
      std::vector<uint8_t> content;
      bool has_content = false;
      OID econtent_type;
      std::vector<X509_Certificate> certs;
      std::vector<SignerInfoData> signer_infos;
};

SignedMessage parse_signed_data(BER_Object content) {
   if(!content.is_a(ASN1_Type::Sequence, ASN1_Class::Constructed)) {
      throw Decoding_Error("CMS SignedData is not a SEQUENCE");
   }

   SignedMessage msg;
   BER_Decoder dec(std::move(content), BER_Decoder::Limits::BER());

   size_t version = 0;
   dec.decode(version);
   if(version != 1 && version != 3) {
      throw Decoding_Error("CMS SignedData has unsupported version");
   }

   // digestAlgorithms lists the digests used by the signers; each
   // SignerInfo carries its own copy, so this set is not enforced
   std::vector<AlgorithmIdentifier> digest_algos;
   dec.decode_list(digest_algos, ASN1_Type::Set, ASN1_Class::Universal);

   BER_Decoder eci = dec.start_sequence();
   eci.decode(msg.econtent_type);
   if(msg.econtent_type != OID::from_string("PKCS7.Data")) {
      throw Decoding_Error(fmt("CMS SignedData with eContentType {} is not supported", msg.econtent_type));
   }
   if(eci.more_items()) {
      BER_Decoder econtent = eci.start_explicit_context_specific(0);
      econtent.decode(msg.content, ASN1_Type::OctetString);
      econtent.end_cons();
      msg.has_content = true;
   }
   eci.end_cons();

   if(dec.peek_next_object().is_a(ASN1_Type(0), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      BER_Decoder certs(dec.get_next_object(), BER_Decoder::Limits::BER());
      while(certs.more_items()) {
         if(!certs.peek_next_object().is_a(ASN1_Type::Sequence, ASN1_Class::Constructed)) {
            throw Decoding_Error("CMS SignedData contains a non-certificate in the certificates field");
         }
         X509_Certificate cert;
         certs.decode(cert);
         msg.certs.push_back(std::move(cert));
      }
   }

   // CRLs may be present for the benefit of other consumers; Botan's
   // CMS does not process revocation data
   if(dec.peek_next_object().is_a(ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      dec.get_next_object();
   }

   BER_Decoder sis = dec.start_set();
   while(sis.more_items()) {
      msg.signer_infos.push_back(decode_signer_info(sis.get_next_object()));
   }
   sis.end_cons();
   dec.verify_end();

   /*
   * Only the SignerInfo clause of the RFC 5652 5.1 version rules can
   * apply here: versions 4 and 5 were rejected above, as were any
   * eContentType other than id-data and any non-certificate entries.
   *    "IF ((certificates is present) AND
   *       (any version 1 attribute certificates are present)) OR
   *       (any SignerInfo structures are version 3) OR
   *       (encapContentInfo eContentType is other than id-data)
   *    THEN version MUST be 3
   *    ELSE version MUST be 1"
   */
   const bool has_version_3_signer = std::ranges::any_of(
      msg.signer_infos, [](const SignerInfoData& signer) { return !signer.sid.is_issuer_and_serial(); });
   const size_t expected_version = has_version_3_signer ? 3 : 1;
   if(version != expected_version) {
      throw Decoding_Error("CMS SignedData has invalid version");
   }

   return msg;
}

}  // namespace

struct Signed_Data_Builder::Signer {
      X509_Certificate cert;
      const Private_Key* key;
      std::string hash_fn;
      std::string padding;
};

Signed_Data_Builder::Signed_Data_Builder() = default;
Signed_Data_Builder::~Signed_Data_Builder() = default;
Signed_Data_Builder::Signed_Data_Builder(Signed_Data_Builder&&) noexcept = default;
Signed_Data_Builder& Signed_Data_Builder::operator=(Signed_Data_Builder&&) noexcept = default;

Signed_Data_Builder& Signed_Data_Builder::add_signer(const X509_Certificate& cert,
                                                     const Private_Key& key,
                                                     std::string_view hash_fn,
                                                     std::string_view padding) {
   m_signers.push_back(Signer{cert, &key, std::string(hash_fn), std::string(padding)});
   return *this;
}

Signed_Data_Builder& Signed_Data_Builder::include_certificate(const X509_Certificate& cert) {
   m_certs.push_back(cert);
   return *this;
}

Signed_Data_Builder& Signed_Data_Builder::detached(bool is_detached) {
   m_detached = is_detached;
   return *this;
}

std::vector<uint8_t> Signed_Data_Builder::sign(std::span<const uint8_t> content, RandomNumberGenerator& rng) const {
   if(m_signers.empty()) {
      throw Invalid_State("CMS Signed_Data_Builder has no signers");
   }

   const OID id_data = OID::from_string("PKCS7.Data");
   const ASN1_Time signing_time(std::chrono::system_clock::now());

   std::vector<AlgorithmIdentifier> digest_algos;
   std::vector<std::vector<uint8_t>> signer_infos;

   for(const auto& signer : m_signers) {
      // Ed25519 and ML-DSA hash internally; the hash_fn choice only
      // affects the message-digest attribute (see digest_for_signer)
      const std::string algo = signer.key->algo_name();
      const bool pure_scheme = (algo == "Ed25519" || algo == "ML-DSA");
      auto pk_signer =
         X509_Object::choose_sig_format(*signer.key, rng, pure_scheme ? "" : signer.hash_fn, signer.padding);

      const std::string digest = digest_for_signer(*signer.key, signer.hash_fn);
      const AlgorithmIdentifier sig_alg = pk_signer->algorithm_identifier();
      try {
         check_signature_algo_allowed(sig_alg);
      } catch(const Decoding_Error&) {
         throw Invalid_Argument(fmt("Unsupported CMS signature algorithm {}", sig_alg.oid()));
      }
      if(!approved_digest(digest) || !signature_digest_matches(sig_alg, digest)) {
         throw Invalid_Argument(
            fmt("CMS signature algorithm {} is incompatible with digest {}", sig_alg.oid(), digest));
      }

      auto hash = HashFunction::create_or_throw(digest);
      const auto content_digest = hash->process<std::vector<uint8_t>>(content.data(), content.size());

      const AlgorithmIdentifier digest_alg(digest, AlgorithmIdentifier::USE_EMPTY_PARAM);
      if(std::find(digest_algos.begin(), digest_algos.end(), digest_alg) == digest_algos.end()) {
         digest_algos.push_back(digest_alg);
      }

      std::vector<uint8_t> content_type_val;
      DER_Encoder(content_type_val).encode(id_data);
      std::vector<uint8_t> digest_val;
      DER_Encoder(digest_val).encode(content_digest, ASN1_Type::OctetString);
      std::vector<uint8_t> time_val;
      DER_Encoder(time_val).encode(signing_time);
      std::vector<uint8_t> protection_val;
      const std::vector<uint8_t> sig_alg_encoding = sig_alg.BER_encode();
      const BER_Object sig_alg_obj = BER_Decoder(sig_alg_encoding, BER_Decoder::Limits::DER()).get_next_object();
      DER_Encoder(protection_val)
         .start_sequence()
         .encode(digest_alg)
         .add_object(ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed, sig_alg_obj.data())
         .end_cons();

      /*
      * RFC 5652 5.4: "A separate encoding of the signedAttrs field is
      * performed for message digest calculation. The IMPLICIT [0] tag
      * in the signedAttrs is not used for the DER encoding, rather an
      * EXPLICIT SET OF tag is used."
      *
      * Encode once with the SET OF tag (which also sorts the set),
      * sign those bytes, then emit with the tag byte swapped to the
      * IMPLICIT [0] used inside the SignerInfo.
      */
      std::vector<uint8_t> attrs_set;
      DER_Encoder(attrs_set)
         .start_set()
         .encode(Attribute(OID::from_string("PKCS9.ContentType"), content_type_val))
         .encode(Attribute(OID::from_string("PKCS9.MessageDigest"), digest_val))
         .encode(Attribute(OID::from_string("PKCS9.SigningTime"), time_val))
         .encode(Attribute(OID::from_string("PKCS9.CMSAlgorithmProtection"), protection_val))
         .end_cons();

      const auto signature = pk_signer->sign_message(attrs_set, rng);

      std::vector<uint8_t> attrs_implicit = attrs_set;
      attrs_implicit[0] = 0xA0;

      std::vector<uint8_t> si;
      DER_Encoder(si)
         .start_sequence()
         .encode(size_t(1))
         .encode(SignerIdentifier(signer.cert))
         .encode(digest_alg)
         .raw_bytes(attrs_implicit)
         .encode(sig_alg)
         .encode(signature, ASN1_Type::OctetString)
         .end_cons();
      signer_infos.push_back(std::move(si));
   }

   std::vector<X509_Certificate> certs;
   certs.reserve(m_signers.size() + m_certs.size());
   for(const auto& signer : m_signers) {
      certs.push_back(signer.cert);
   }
   for(const auto& cert : m_certs) {
      if(std::find(certs.begin(), certs.end(), cert) == certs.end()) {
         certs.push_back(cert);
      }
   }

   std::vector<uint8_t> body;
   DER_Encoder enc(body);
   enc.start_sequence();
   enc.encode(size_t(1));
   enc.start_set();
   for(const auto& algo : digest_algos) {
      enc.encode(algo);
   }
   enc.end_cons();

   enc.start_sequence().encode(id_data);
   if(!m_detached) {
      enc.start_explicit_context_specific(0).encode(content, ASN1_Type::OctetString).end_cons();
   }
   enc.end_cons();

   enc.start_set(ASN1_Type(0), ASN1_Class::ContextSpecific);
   for(const auto& cert : certs) {
      enc.encode(cert);
   }
   enc.end_cons();

   enc.start_set();
   for(const auto& si : signer_infos) {
      enc.raw_bytes(si);
   }
   enc.end_cons();
   enc.end_cons();

   return make_content_info(OID::from_string("PKCS7.SignedData"), body);
}

Signed_Data_Verification::Signed_Data_Verification(std::vector<X509_Certificate> signers,
                                                   std::optional<std::vector<uint8_t>> content,
                                                   std::optional<Path_Validation_Result> path_result) :
      m_signers(std::move(signers)), m_content(std::move(content)), m_path_result(std::move(path_result)) {}

const std::vector<uint8_t>& Signed_Data_Verification::content() const {
   BOTAN_STATE_CHECK(m_content.has_value());
   return *m_content;
}

Signed_Data_Verification verify(std::span<const uint8_t> content_info,
                                std::optional<std::span<const uint8_t>> detached_content,
                                Certificate_Store* trusted_roots,
                                std::chrono::system_clock::time_point validation_time) {
   auto [content_type, content] = open_content_info(content_info);
   if(content_type != OID::from_string("PKCS7.SignedData")) {
      throw Decoding_Error(fmt("CMS content type {} is not SignedData", content_type));
   }

   SignedMessage msg = parse_signed_data(std::move(content));

   if(msg.has_content == detached_content.has_value()) {
      throw Invalid_Argument(msg.has_content ? "CMS message is attached but detached content was given"
                                             : "CMS message is detached and requires the content");
   }
   const std::span<const uint8_t> data = msg.has_content ? std::span<const uint8_t>(msg.content) : *detached_content;

   if(msg.signer_infos.empty()) {
      throw Invalid_Argument("CMS SignedData contains no signers");
   }

   std::vector<X509_Certificate> signers;
   std::optional<Path_Validation_Result> path_result;

   for(const auto& si : msg.signer_infos) {
      check_signature_algo_allowed(si.sig_alg);

      const std::string sig_algo_name = si.sig_alg.oid().human_name_or_empty();
      const bool ignore_digest_alg = is_ml_dsa(sig_algo_name) && !si.signed_attrs_set;
      const std::string digest = ignore_digest_alg ? std::string{} : approved_digest_algo(si.digest_alg);
      if(!ignore_digest_alg && !signature_digest_matches(si.sig_alg, digest)) {
         throw Decoding_Error("CMS SignerInfo digest algorithm is incompatible with signature algorithm");
      }

      std::vector<uint8_t> content_digest;
      if(si.signed_attrs_set) {
         auto hash = HashFunction::create_or_throw(digest);
         content_digest = hash->process<std::vector<uint8_t>>(data.data(), data.size());
      }

      std::optional<X509_Certificate> signer_cert;
      for(const auto& cert : msg.certs) {
         if(si.sid.matches(cert)) {
            signer_cert = cert;
            break;
         }
      }
      if(!signer_cert && trusted_roots != nullptr && si.sid.is_issuer_and_serial()) {
         const auto& iasn = si.sid.issuer_and_serial();
         // The store lookup is by magnitude only, so recheck the sign
         auto found = trusted_roots->find_cert_by_issuer_dn_and_serial_number(iasn.issuer(), iasn.serial().magnitude());
         if(found && iasn.matches(*found)) {
            signer_cert = std::move(found);
         }
      }
      if(!signer_cert) {
         throw Verification_Error("unable to locate the certificate of a signer");
      }

      std::span<const uint8_t> signed_bytes = data;
      if(si.signed_attrs_set) {
         check_signed_attrs(*si.signed_attrs_set, msg.econtent_type, content_digest, si.digest_alg, si.sig_alg);
         signed_bytes = *si.signed_attrs_set;
      }

      const auto pubkey = signer_cert->subject_public_key();
      // With the bare rsaEncryption identifier the digest is not part
      // of the signature algorithm; it comes from the digestAlgorithm
      PK_Verifier verifier = (si.sig_alg.oid() == OID::from_string("RSA"))
                                ? PK_Verifier(*pubkey, fmt("PKCS1v15({})", digest))
                                : PK_Verifier(*pubkey, si.sig_alg);
      if(!verifier.verify_message(signed_bytes, si.signature)) {
         throw Verification_Error("signature verification failed");
      }

      signers.push_back(*signer_cert);

      if(trusted_roots != nullptr) {
         std::vector<X509_Certificate> chain;
         chain.push_back(*signer_cert);
         for(const auto& cert : msg.certs) {
            if(cert != *signer_cert) {
               chain.push_back(cert);
            }
         }

         Path_Validation_Result signer_path_result = x509_path_validate(chain,
                                                                        Path_Validation_Restrictions(),
                                                                        {trusted_roots},
                                                                        /*hostname=*/"",
                                                                        Usage_Type::UNSPECIFIED,
                                                                        validation_time);

         // With several signers, a failed validation takes precedence
         // so that a caller checking path_result sees the failure
         if(!path_result.has_value() || path_result->successful_validation()) {
            path_result = std::move(signer_path_result);
         }
      }
   }

   std::optional<std::vector<uint8_t>> verified_content;
   if(msg.has_content) {
      verified_content = std::move(msg.content);
   }

   return Signed_Data_Verification(std::move(signers), std::move(verified_content), std::move(path_result));
}

}  // namespace Botan::CMS

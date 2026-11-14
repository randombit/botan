/*
* CMS EnvelopedData and AuthEnvelopedData
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cms.h>

#include <botan/aead.h>
#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/cipher_mode.h>
#include <botan/der_enc.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/x509cert.h>
#include <botan/internal/cms_helpers.h>
#include <botan/internal/fmt.h>

namespace Botan::CMS {

namespace {

constexpr const char* KTRI_OAEP_PADDING = "OAEP(SHA-256)";
constexpr const char* KTRI_PKCS1_PADDING = "PKCS1v15";

bool content_algo_is_aead(std::string_view algo) {
   if(algo == "AES-128/GCM" || algo == "AES-256/GCM") {
      return true;
   }
   if(algo == "AES-128/CBC" || algo == "AES-256/CBC") {
      return false;
   }
   throw Invalid_Argument(fmt("Unsupported CMS content encryption algorithm '{}'", algo));
}

/*
* RFC 8017 A.2.1:
*    RSAES-OAEP-params ::= SEQUENCE {
*        hashAlgorithm      [0] HashAlgorithm     DEFAULT sha1,
*        maskGenAlgorithm   [1] MaskGenAlgorithm  DEFAULT mgf1SHA1,
*        pSourceAlgorithm   [2] PSourceAlgorithm  DEFAULT pSpecifiedEmpty
*    }
*/
std::vector<uint8_t> oaep_sha256_parameters() {
   const AlgorithmIdentifier hash_id("SHA-256", AlgorithmIdentifier::USE_NULL_PARAM);
   const AlgorithmIdentifier mgf1_id(OID::from_string("MGF1"), hash_id.BER_encode());

   std::vector<uint8_t> params;
   DER_Encoder(params)
      .start_sequence()
      .start_explicit_context_specific(0)
      .encode(hash_id)
      .end_cons()
      .start_explicit_context_specific(1)
      .encode(mgf1_id)
      .end_cons()
      .end_cons();
   return params;
}

std::string allowed_oaep_hash(const AlgorithmIdentifier& hash_id) {
   if(!hash_id.parameters_are_null_or_empty()) {
      throw Decoding_Error("CMS OAEP hash AlgorithmIdentifier has unexpected parameters");
   }
   const std::string name = hash_id.oid().human_name_or_empty();
   if(name == "SHA-1" || name == "SHA-224" || name == "SHA-256" || name == "SHA-384" || name == "SHA-512") {
      return name;
   }
   throw Decoding_Error(fmt("CMS OAEP with unsupported hash {}", hash_id.oid()));
}

std::string oaep_padding_from_params(std::span<const uint8_t> params) {
   std::optional<AlgorithmIdentifier> hash_alg;
   std::optional<AlgorithmIdentifier> mgf_alg;
   std::optional<AlgorithmIdentifier> psource_alg;

   BER_Decoder dec(params, BER_Decoder::Limits::DER());
   dec.start_sequence()
      .decode_optional(hash_alg, ASN1_Type(0), ASN1_Class::ExplicitContextSpecific)
      .decode_optional(mgf_alg, ASN1_Type(1), ASN1_Class::ExplicitContextSpecific)
      .decode_optional(psource_alg, ASN1_Type(2), ASN1_Class::ExplicitContextSpecific)
      .end_cons();
   dec.verify_end();

   if(psource_alg) {
      throw Decoding_Error("CMS OAEP with pSourceAlgorithm is not supported");
   }

   const std::string hash = hash_alg ? allowed_oaep_hash(*hash_alg) : "SHA-1";

   std::string mgf_hash = "SHA-1";
   if(mgf_alg) {
      if(mgf_alg->oid() != OID::from_string("MGF1")) {
         throw Decoding_Error(fmt("CMS OAEP with unsupported mask generation function {}", mgf_alg->oid()));
      }
      AlgorithmIdentifier mgf_hash_id;
      BER_Decoder mgf_params(mgf_alg->parameters(), BER_Decoder::Limits::DER());
      mgf_params.decode(mgf_hash_id).verify_end();
      mgf_hash = allowed_oaep_hash(mgf_hash_id);
   }

   return fmt("OAEP({},MGF1({}))", hash, mgf_hash);
}

/*
* RFC 5084 3.2:
*    GCMParameters ::= SEQUENCE {
*      aes-nonce        OCTET STRING, -- recommended size is 12 octets
*      aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
*/
std::vector<uint8_t> gcm_parameters(std::span<const uint8_t> nonce, size_t icv_len) {
   std::vector<uint8_t> params;
   DER_Encoder enc(params);
   enc.start_sequence().encode(nonce, ASN1_Type::OctetString);
   if(icv_len != 12) {
      enc.encode(icv_len);
   }
   enc.end_cons();
   return params;
}

std::pair<std::vector<uint8_t>, size_t> decode_gcm_parameters(std::span<const uint8_t> params) {
   std::vector<uint8_t> nonce;
   size_t icv_len = 12;

   BER_Decoder dec(params, BER_Decoder::Limits::DER());
   dec.start_sequence()
      .decode(nonce, ASN1_Type::OctetString)
      .decode_default(icv_len, ASN1_Type::Integer, ASN1_Class::Universal, size_t(12))
      .end_cons();
   dec.verify_end();

   if(nonce.empty() || nonce.size() > 64) {
      throw Decoding_Error("CMS GCMParameters nonce has invalid length");
   }
   if(icv_len < 12 || icv_len > 16) {
      throw Decoding_Error("CMS GCMParameters ICV length out of range");
   }
   return {std::move(nonce), icv_len};
}

struct EncryptedContentInfo {
      OID content_type;
      AlgorithmIdentifier cipher_alg;
      std::vector<uint8_t> ciphertext;
      bool has_content = false;
};

void encode_encrypted_content_info(DER_Encoder& enc,
                                   const OID& content_type,
                                   const AlgorithmIdentifier& cipher_alg,
                                   std::span<const uint8_t> ciphertext) {
   enc.start_sequence()
      .encode(content_type)
      .encode(cipher_alg)
      .encode(ciphertext, ASN1_Type::OctetString, ASN1_Type(0), ASN1_Class::ContextSpecific)
      .end_cons();
}

EncryptedContentInfo decode_encrypted_content_info(BER_Decoder& dec) {
   EncryptedContentInfo eci;
   BER_Decoder seq = dec.start_sequence();
   seq.decode(eci.content_type).decode(eci.cipher_alg);
   if(seq.more_items()) {
      seq.decode(eci.ciphertext, ASN1_Type::OctetString, ASN1_Type(0), ASN1_Class::ContextSpecific);
      eci.has_content = true;
   }
   seq.end_cons();
   return eci;
}

size_t decode_implicit_sequence_version(const BER_Object& obj) {
   std::vector<uint8_t> sequence;
   DER_Encoder(sequence).add_object(ASN1_Type::Sequence, ASN1_Class::Universal | ASN1_Class::Constructed, obj.data());
   BER_Decoder outer(sequence, BER_Decoder::Limits::BER());
   BER_Decoder inner = outer.start_sequence();
   size_t version = 0;
   inner.decode(version);
   return version;
}

struct OriginatorInfoVersionRequirements {
      bool has_v2_attribute_certificate = false;
      bool has_other_certificate_or_crl = false;
};

OriginatorInfoVersionRequirements inspect_originator_info(const BER_Object& obj) {
   std::vector<uint8_t> sequence;
   DER_Encoder(sequence).add_object(ASN1_Type::Sequence, ASN1_Class::Universal | ASN1_Class::Constructed, obj.data());
   BER_Decoder outer(sequence, BER_Decoder::Limits::BER());
   BER_Decoder info = outer.start_sequence();

   OriginatorInfoVersionRequirements requirements;
   bool certs_seen = false;
   bool crls_seen = false;
   while(info.more_items()) {
      const BER_Object field = info.get_next_object();
      if(field.is_a(ASN1_Type(0), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         if(certs_seen || crls_seen) {
            throw Decoding_Error("CMS OriginatorInfo contains duplicate or out-of-order certificates fields");
         }
         certs_seen = true;

         std::vector<uint8_t> cert_set;
         DER_Encoder(cert_set).add_object(
            ASN1_Type::Set, ASN1_Class::Universal | ASN1_Class::Constructed, field.data());
         BER_Decoder cert_choices(cert_set, BER_Decoder::Limits::BER());
         while(cert_choices.more_items()) {
            const BER_Object choice = cert_choices.get_next_object();
            requirements.has_v2_attribute_certificate |=
               choice.is_a(ASN1_Type(2), ASN1_Class::ContextSpecific | ASN1_Class::Constructed);
            requirements.has_other_certificate_or_crl |=
               choice.is_a(ASN1_Type(3), ASN1_Class::ContextSpecific | ASN1_Class::Constructed);
         }
         cert_choices.verify_end();
      } else if(field.is_a(ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         if(crls_seen) {
            throw Decoding_Error("CMS OriginatorInfo contains duplicate crls fields");
         }
         crls_seen = true;

         std::vector<uint8_t> crl_set;
         DER_Encoder(crl_set).add_object(ASN1_Type::Set, ASN1_Class::Universal | ASN1_Class::Constructed, field.data());
         BER_Decoder crl_choices(crl_set, BER_Decoder::Limits::BER());
         while(crl_choices.more_items()) {
            const BER_Object choice = crl_choices.get_next_object();
            requirements.has_other_certificate_or_crl |=
               choice.is_a(ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed);
         }
         crl_choices.verify_end();
      } else {
         throw Decoding_Error("CMS OriginatorInfo has an unexpected field");
      }
   }

   info.end_cons();
   outer.verify_end();
   return requirements;
}

/*
* Recover the plaintext given the CEK. For AEAD modes @p mac holds the
* tag from the AuthEnvelopedData mac field and @p aad the AAD encoding
* (the re-tagged authAttrs, or empty).
*/
secure_vector<uint8_t> decrypt_content(const EncryptedContentInfo& eci,
                                       std::span<const uint8_t> cek,
                                       std::span<const uint8_t> mac,
                                       std::span<const uint8_t> aad,
                                       bool expect_aead) {
   if(!eci.has_content) {
      throw Decoding_Error("CMS encryptedContent is absent, cannot decrypt");
   }

   const std::string cipher_name = [&]() -> std::string {
      const std::string name = eci.cipher_alg.oid().human_name_or_empty();
      const bool is_cbc = (name == "AES-128/CBC" || name == "AES-192/CBC" || name == "AES-256/CBC");
      const bool is_gcm = (name == "AES-128/GCM" || name == "AES-192/GCM" || name == "AES-256/GCM");
      if(is_cbc == expect_aead || (!is_cbc && !is_gcm)) {
         throw Decoding_Error(fmt("Unsupported CMS content encryption algorithm {}", eci.cipher_alg.oid()));
      }
      return name;
   }();

   std::vector<uint8_t> nonce;
   secure_vector<uint8_t> buf;

   std::unique_ptr<Cipher_Mode> cipher;

   if(expect_aead) {
      auto [gcm_nonce, icv_len] = decode_gcm_parameters(eci.cipher_alg.parameters());
      if(mac.size() != icv_len) {
         throw Decoding_Error("CMS AuthEnvelopedData mac length does not match aes-ICVlen");
      }
      nonce = std::move(gcm_nonce);

      auto aead = AEAD_Mode::create_or_throw(fmt("{}({})", cipher_name, icv_len), Cipher_Dir::Decryption);
      aead->set_key(cek);
      aead->set_associated_data(aad);
      cipher = std::move(aead);

      buf.assign(eci.ciphertext.begin(), eci.ciphertext.end());
      buf.insert(buf.end(), mac.begin(), mac.end());
   } else {
      cipher = Cipher_Mode::create_or_throw(cipher_name, Cipher_Dir::Decryption);

      BER_Decoder param_dec(eci.cipher_alg.parameters(), BER_Decoder::Limits::DER());
      param_dec.decode(nonce, ASN1_Type::OctetString).verify_end();
      if(nonce.size() != cipher->default_nonce_length()) {
         throw Decoding_Error("CMS content encryption AlgorithmIdentifier has invalid IV length");
      }
      cipher->set_key(cek);

      buf.assign(eci.ciphertext.begin(), eci.ciphertext.end());
   }

   try {
      cipher->start(nonce);
      cipher->finish(buf);
   } catch(Invalid_Authentication_Tag&) {
      throw Decryption_Error("content authentication failure");
   } catch(Decoding_Error&) {
      throw Decryption_Error("content decryption failed");
   }

   return buf;
}

struct Ktri {
      SignerIdentifier rid;
      AlgorithmIdentifier key_enc_alg;
      std::vector<uint8_t> encrypted_key;
};

Ktri decode_ktri(const BER_Object& obj) {
   Ktri ktri;
   size_t version = 0;

   BER_Decoder dec(obj, BER_Decoder::Limits::BER());
   dec.decode(version).decode(ktri.rid).decode(ktri.key_enc_alg).decode(ktri.encrypted_key, ASN1_Type::OctetString);
   dec.verify_end();

   /*
   * RFC 5652 6.2.1: "If the RecipientIdentifier is the CHOICE
   * issuerAndSerialNumber, then the version MUST be 0. If the
   * RecipientIdentifier is subjectKeyIdentifier, then the version
   * MUST be 2."
   */
   const size_t expected_version = ktri.rid.is_issuer_and_serial() ? 0 : 2;
   if(version != expected_version) {
      throw Decoding_Error("CMS KeyTransRecipientInfo has invalid version");
   }

   return ktri;
}

secure_vector<uint8_t> ktri_decrypt_cek(const Ktri& ktri,
                                        const Private_Key& key,
                                        size_t cek_len,
                                        RandomNumberGenerator& rng) {
   const std::string padding = [&]() -> std::string {
      if(ktri.key_enc_alg.oid() == OID::from_string("RSA")) {
         if(!ktri.key_enc_alg.parameters_are_null_or_empty()) {
            throw Decoding_Error("CMS RSA keyEncryptionAlgorithm has unexpected parameters");
         }
         return KTRI_PKCS1_PADDING;
      } else if(ktri.key_enc_alg.oid() == OID::from_string("RSA/OAEP")) {
         return oaep_padding_from_params(ktri.key_enc_alg.parameters());
      } else {
         throw Decryption_Error(fmt("unsupported key encryption algorithm {}", ktri.key_enc_alg.oid()));
      }
   }();

   const PK_Decryptor_EME decryptor(key, rng, padding);
   // An invalid encryptedKey yields a random CEK here; the subsequent
   // content decryption then fails, without a padding oracle
   return decryptor.decrypt_or_random(ktri.encrypted_key.data(), ktri.encrypted_key.size(), cek_len, rng);
}

struct EnvelopedMessage {
      std::vector<BER_Object> recipient_infos;
      EncryptedContentInfo eci;
      std::vector<uint8_t> mac;
      std::vector<uint8_t> aad;
      bool is_authenticated = false;
};

EnvelopedMessage parse_enveloped_data(BER_Object content, bool authenticated) {
   EnvelopedMessage msg;
   msg.is_authenticated = authenticated;

   if(!content.is_a(ASN1_Type::Sequence, ASN1_Class::Constructed)) {
      throw Decoding_Error("CMS EnvelopedData is not a SEQUENCE");
   }

   BER_Decoder dec(std::move(content), BER_Decoder::Limits::BER());

   size_t version = 0;
   dec.decode(version);
   OriginatorInfoVersionRequirements originator_info;
   bool has_originator_info = false;
   if(authenticated) {
      /*
      * RFC 5083 2.1: "version is the syntax version number. It MUST
      * be set to 0."
      */
      if(version != 0) {
         throw Decoding_Error("CMS AuthEnvelopedData has invalid version");
      }
   } else {
      if(version != 0 && version != 2 && version != 3 && version != 4) {
         throw Decoding_Error("CMS EnvelopedData has invalid version");
      }
   }

   // OriginatorInfo carries optional certificates and CRLs; only choice
   // tags are inspected to determine the enclosing version.
   if(dec.peek_next_object().is_a(ASN1_Type(0), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      originator_info = inspect_originator_info(dec.get_next_object());
      has_originator_info = true;
   }

   BER_Decoder ris = dec.start_set();
   while(ris.more_items()) {
      msg.recipient_infos.push_back(ris.get_next_object());
   }
   ris.end_cons();
   if(msg.recipient_infos.empty()) {
      throw Decoding_Error("CMS message has no RecipientInfos");
   }

   bool requires_version_2 = false;
   bool requires_version_3 = false;
   for(const BER_Object& ri : msg.recipient_infos) {
      if(ri.is_a(ASN1_Type::Sequence, ASN1_Class::Constructed)) {
         const Ktri ktri = decode_ktri(ri);
         requires_version_2 |= !ktri.rid.is_issuer_and_serial();
      } else if(ri.is_a(ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         if(decode_implicit_sequence_version(ri) != 3) {
            throw Decoding_Error("CMS KeyAgreeRecipientInfo has invalid version");
         }
         requires_version_2 = true;
      } else if(ri.is_a(ASN1_Type(2), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         if(decode_implicit_sequence_version(ri) != 4) {
            throw Decoding_Error("CMS KEKRecipientInfo has invalid version");
         }
         requires_version_2 = true;
      } else if(ri.is_a(ASN1_Type(3), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         if(decode_implicit_sequence_version(ri) != 0) {
            throw Decoding_Error("CMS PasswordRecipientInfo has invalid version");
         }
         requires_version_3 = true;
      } else if(ri.is_a(ASN1_Type(4), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         requires_version_3 = true;
      } else {
         throw Decoding_Error("CMS RecipientInfo has unexpected tag");
      }
   }

   msg.eci = decode_encrypted_content_info(dec);
   if(msg.eci.content_type != OID::from_string("PKCS7.Data")) {
      throw Decoding_Error(fmt("CMS EncryptedContentInfo content type {} is not supported", msg.eci.content_type));
   }

   if(authenticated) {
      /*
      * RFC 5083 2.2: "For the purposes of constructing the AAD, the
      * IMPLICIT [1] tag in the authAttrs field is not used for the DER
      * encoding: rather a universal SET OF tag is used."
      */
      if(dec.peek_next_object().is_a(ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         msg.aad = attrs_as_set_encoding(dec.get_next_object());
      }
      dec.decode(msg.mac, ASN1_Type::OctetString);
      // unauthAttrs [2] are not authenticated; skip them
      if(dec.peek_next_object().is_a(ASN1_Type(2), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         dec.get_next_object();
      }
   } else {
      // unprotectedAttrs [1] are not protected; skip them
      if(dec.peek_next_object().is_a(ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         dec.get_next_object();
         requires_version_2 = true;
      }
   }

   dec.verify_end();

   if(!authenticated) {
      /*
      * RFC 5652 6.1:
      *    "IF (originatorInfo is present) AND
      *       ((any certificates with a type of other are present) OR
      *       (any crls with a type of other are present))
      *    THEN version is 4
      *    ELSE
      *       IF ((originatorInfo is present) AND
      *          (any version 2 attribute certificates are present)) OR
      *          (any RecipientInfo structures include pwri) OR
      *          (any RecipientInfo structures include ori)
      *       THEN version is 3
      *       ELSE
      *          IF (originatorInfo is absent) AND
      *             (unprotectedAttrs is absent) AND
      *             (all RecipientInfo structures are version 0)
      *          THEN version is 0
      *          ELSE version is 2"
      */
      size_t expected_version = 0;
      if(originator_info.has_other_certificate_or_crl) {
         expected_version = 4;
      } else if(originator_info.has_v2_attribute_certificate || requires_version_3) {
         expected_version = 3;
      } else if(has_originator_info || requires_version_2) {
         expected_version = 2;
      }
      if(version != expected_version) {
         throw Decoding_Error("CMS EnvelopedData has invalid version");
      }
   }

   return msg;
}

}  // namespace

struct Enveloped_Data_Builder::Recipient {
      enum class Type : uint8_t { Ktri, Kemri };

      Type type;
      X509_Certificate cert;
      std::string padding;
};

Enveloped_Data_Builder::Enveloped_Data_Builder() : m_content_enc_algo("AES-256/GCM") {}

Enveloped_Data_Builder::~Enveloped_Data_Builder() = default;
Enveloped_Data_Builder::Enveloped_Data_Builder(Enveloped_Data_Builder&&) noexcept = default;
Enveloped_Data_Builder& Enveloped_Data_Builder::operator=(Enveloped_Data_Builder&&) noexcept = default;

Enveloped_Data_Builder& Enveloped_Data_Builder::add_ktri_recipient(const X509_Certificate& cert,
                                                                   std::string_view padding) {
   if(padding != KTRI_OAEP_PADDING && padding != KTRI_PKCS1_PADDING) {
      throw Invalid_Argument(fmt("Unsupported CMS key transport padding '{}'", padding));
   }
   auto pubkey = cert.subject_public_key();
   if(pubkey->algo_name() != "RSA") {
      throw Invalid_Argument("CMS key transport requires an RSA certificate");
   }
   m_recipients.push_back(Recipient{Recipient::Type::Ktri, cert, std::string(padding)});
   return *this;
}

Enveloped_Data_Builder& Enveloped_Data_Builder::add_kem_recipient(const X509_Certificate& cert) {
   m_recipients.push_back(Recipient{Recipient::Type::Kemri, cert, ""});
   return *this;
}

Enveloped_Data_Builder& Enveloped_Data_Builder::set_content_encryption(std::string_view algo) {
   content_algo_is_aead(algo);  // throws on unsupported algos
   m_content_enc_algo = algo;
   return *this;
}

std::vector<uint8_t> Enveloped_Data_Builder::build(std::span<const uint8_t> content, RandomNumberGenerator& rng) const {
   if(m_recipients.empty()) {
      throw Invalid_State("CMS Enveloped_Data_Builder has no recipients");
   }

   const bool aead = content_algo_is_aead(m_content_enc_algo);

   auto cipher = Cipher_Mode::create_or_throw(m_content_enc_algo, Cipher_Dir::Encryption);
   const auto cek = rng.random_vec<secure_vector<uint8_t>>(cipher->key_spec().maximum_keylength());
   const auto nonce = rng.random_vec<std::vector<uint8_t>>(cipher->default_nonce_length());

   std::vector<uint8_t> cipher_params;
   if(aead) {
      cipher_params = gcm_parameters(nonce, cipher->tag_size());
   } else {
      DER_Encoder(cipher_params).encode(nonce, ASN1_Type::OctetString);
   }
   const AlgorithmIdentifier cipher_alg(OID::from_string(m_content_enc_algo), cipher_params);

   cipher->set_key(cek);
   cipher->start(nonce);
   secure_vector<uint8_t> ctext(content.begin(), content.end());
   cipher->finish(ctext);

   // In AuthEnvelopedData the tag is carried in the mac field, not
   // appended to encryptedContent
   std::vector<uint8_t> mac;
   if(aead) {
      const size_t tag_size = cipher->tag_size();
      BOTAN_ASSERT_NOMSG(ctext.size() >= tag_size);
      mac.assign(ctext.end() - tag_size, ctext.end());
      ctext.resize(ctext.size() - tag_size);
   }

   std::vector<std::vector<uint8_t>> recipient_infos;
   bool any_kemri = false;
   for(const auto& recipient : m_recipients) {
      if(recipient.type == Recipient::Type::Ktri) {
         const auto pubkey = recipient.cert.subject_public_key();

         AlgorithmIdentifier key_enc_alg;
         if(recipient.padding == KTRI_PKCS1_PADDING) {
            key_enc_alg = AlgorithmIdentifier("RSA", AlgorithmIdentifier::USE_NULL_PARAM);
         } else {
            key_enc_alg = AlgorithmIdentifier("RSA/OAEP", oaep_sha256_parameters());
         }

         const PK_Encryptor_EME encryptor(*pubkey, rng, recipient.padding);
         const auto encrypted_key = encryptor.encrypt(cek, rng);

         std::vector<uint8_t> ri;
         DER_Encoder(ri)
            .start_sequence()
            .encode(size_t(0))
            .encode(SignerIdentifier(recipient.cert))
            .encode(key_enc_alg)
            .encode(encrypted_key, ASN1_Type::OctetString)
            .end_cons();
         recipient_infos.push_back(std::move(ri));
      } else {
         recipient_infos.push_back(kemri_create(recipient.cert, cek, rng));
         any_kemri = true;
      }
   }

   /*
   * RFC 5652 6.1: "IF ... (any RecipientInfo structures include pwri) OR
   * (any RecipientInfo structures include ori) THEN version is 3 ...
   * IF (originatorInfo is absent) AND (unprotectedAttrs is absent) AND
   * (all RecipientInfo structures are version 0) THEN version is 0"
   */
   size_t version = 0;
   if(!aead && any_kemri) {
      version = 3;
   }

   std::vector<uint8_t> body;
   DER_Encoder enc(body);
   enc.start_sequence().encode(version);
   enc.start_set();
   for(const auto& ri : recipient_infos) {
      enc.raw_bytes(ri);
   }
   enc.end_cons();
   encode_encrypted_content_info(enc, OID::from_string("PKCS7.Data"), cipher_alg, ctext);
   if(aead) {
      enc.encode(mac, ASN1_Type::OctetString);
   }
   enc.end_cons();

   const OID content_type = aead ? OID::from_string("CMS.AuthEnvelopedData") : OID::from_string("PKCS7.EnvelopedData");
   return make_content_info(content_type, body);
}

secure_vector<uint8_t> decrypt(std::span<const uint8_t> content_info,
                               const Private_Key& key,
                               const X509_Certificate& cert,
                               RandomNumberGenerator& rng) {
   auto [content_type, content] = open_content_info(content_info);

   const bool authenticated = (content_type == OID::from_string("CMS.AuthEnvelopedData"));
   if(!authenticated && content_type != OID::from_string("PKCS7.EnvelopedData")) {
      throw Decoding_Error(fmt("CMS content type {} is not an enveloped message", content_type));
   }

   EnvelopedMessage msg = parse_enveloped_data(std::move(content), authenticated);

   const size_t cek_len = [&]() {
      const std::string name = msg.eci.cipher_alg.oid().human_name_or_empty();
      if(auto cipher = Cipher_Mode::create(name, Cipher_Dir::Decryption)) {
         return cipher->key_spec().maximum_keylength();
      }
      throw Decoding_Error(fmt("Unsupported CMS content encryption algorithm {}", msg.eci.cipher_alg.oid()));
   }();

   std::optional<secure_vector<uint8_t>> cek;

   for(const BER_Object& ri : msg.recipient_infos) {
      if(ri.is_a(ASN1_Type::Sequence, ASN1_Class::Constructed)) {
         const Ktri ktri = decode_ktri(ri);
         if(!ktri.rid.matches(cert)) {
            continue;
         }
         cek = ktri_decrypt_cek(ktri, key, cek_len, rng);
      } else if(ri.is_a(ASN1_Type(4), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         cek = kemri_try_decrypt(ri.data(), key, cert, rng);
      } else if(ri.is_a(ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed) ||
                ri.is_a(ASN1_Type(2), ASN1_Class::ContextSpecific | ASN1_Class::Constructed) ||
                ri.is_a(ASN1_Type(3), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         // kari, kekri and pwri recipients are not supported; skip them
         continue;
      } else {
         throw Decoding_Error("CMS RecipientInfo has unexpected tag");
      }

      if(cek) {
         break;
      }
   }

   if(!cek) {
      throw Invalid_Argument("No CMS RecipientInfo matches the given certificate");
   }

   return decrypt_content(msg.eci, *cek, msg.mac, msg.aad, authenticated);
}

}  // namespace Botan::CMS

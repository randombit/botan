/*
* CMS KEMRecipientInfo (RFC 9629)
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cms.h>

#include <botan/ber_dec.h>
#include <botan/block_cipher.h>
#include <botan/der_enc.h>
#include <botan/kdf.h>
#include <botan/nist_keywrap.h>
#include <botan/pubkey.h>
#include <botan/x509cert.h>
#include <botan/internal/cms_helpers.h>
#include <botan/internal/fmt.h>

namespace Botan::CMS {

namespace {

bool is_ml_kem_oid_name(std::string_view name) {
   return name == "ML-KEM-512" || name == "ML-KEM-768" || name == "ML-KEM-1024";
}

std::string block_cipher_for_wrap(const OID& wrap_oid) {
   const std::string name = wrap_oid.human_name_or_empty();
   if(name == "KeyWrap.AES-128") {
      return "AES-128";
   } else if(name == "KeyWrap.AES-192") {
      return "AES-192";
   } else if(name == "KeyWrap.AES-256") {
      return "AES-256";
   }
   throw Decoding_Error(fmt("CMS KEMRecipientInfo with unsupported key wrap algorithm {}", wrap_oid));
}

std::string kdf_for_oid(const OID& kdf_oid) {
   const std::string name = kdf_oid.human_name_or_empty();
   if(name == "HKDF(SHA-256)" || name == "HKDF(SHA-384)" || name == "HKDF(SHA-512)") {
      return name;
   }
   throw Decoding_Error(fmt("CMS KEMRecipientInfo with unsupported KDF {}", kdf_oid));
}

/*
* RFC 9629 5:
*    CMSORIforKEMOtherInfo ::= SEQUENCE {
*      wrap KeyEncryptionAlgorithmIdentifier,
*      kekLength INTEGER (1..65535),
*      ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL }
*/
std::vector<uint8_t> kem_other_info(const AlgorithmIdentifier& wrap_alg,
                                    size_t kek_len,
                                    const std::optional<std::vector<uint8_t>>& ukm) {
   std::vector<uint8_t> out;
   DER_Encoder enc(out);
   enc.start_sequence().encode(wrap_alg).encode(kek_len);
   if(ukm) {
      enc.start_explicit_context_specific(0).encode(*ukm, ASN1_Type::OctetString).end_cons();
   }
   enc.end_cons();
   return out;
}

secure_vector<uint8_t> derive_kek(std::string_view kdf_name,
                                  std::span<const uint8_t> shared_secret,
                                  size_t kek_len,
                                  const AlgorithmIdentifier& wrap_alg,
                                  const std::optional<std::vector<uint8_t>>& ukm) {
   auto kdf = KDF::create_or_throw(kdf_name);
   const auto info = kem_other_info(wrap_alg, kek_len, ukm);
   // RFC 9936 2.2.1: "the salt parameter is unused; that is, it is the
   // zero-length string"
   return kdf->derive_key(kek_len, shared_secret, {}, info);
}

}  // namespace

std::vector<uint8_t> kemri_create(const X509_Certificate& cert,
                                  std::span<const uint8_t> cek,
                                  RandomNumberGenerator& rng) {
   auto pubkey = cert.subject_public_key();
   if(!is_ml_kem_oid_name(pubkey->object_identifier().human_name_or_empty())) {
      throw Invalid_Argument("CMS KEM recipient requires an ML-KEM certificate");
   }
   const Key_Constraints key_usage = cert.constraints();
   if(!key_usage.empty() && key_usage != Key_Constraints::KeyEncipherment) {
      throw Invalid_Argument("CMS ML-KEM certificate keyUsage must be keyEncipherment only");
   }

   PK_KEM_Encryptor kem(*pubkey, "Raw");
   const auto encap = kem.encrypt(rng);

   const size_t kek_len = 32;
   const AlgorithmIdentifier wrap_alg(OID::from_string("KeyWrap.AES-256"), AlgorithmIdentifier::USE_EMPTY_PARAM);
   const AlgorithmIdentifier kdf_alg(OID::from_string("HKDF(SHA-256)"), AlgorithmIdentifier::USE_EMPTY_PARAM);

   const auto kek = derive_kek("HKDF(SHA-256)", encap.shared_key(), kek_len, wrap_alg, std::nullopt);

   auto aes = BlockCipher::create_or_throw("AES-256");
   aes->set_key(kek);
   const auto wrapped_cek = nist_key_wrap(cek.data(), cek.size(), *aes);

   std::vector<uint8_t> out;
   DER_Encoder(out)
      .start_context_specific(4)  // ori, holding OtherRecipientInfo
      .encode(OID::from_string("CMS.KEMRecipientInfo"))
      .start_sequence()  // KEMRecipientInfo
      .encode(size_t(0))
      .encode(SignerIdentifier(cert))
      .encode(pubkey->algorithm_identifier())
      .encode(encap.encapsulated_shared_key(), ASN1_Type::OctetString)
      .encode(kdf_alg)
      .encode(kek_len)
      .encode(wrap_alg)
      .encode(wrapped_cek, ASN1_Type::OctetString)
      .end_cons()
      .end_cons();
   return out;
}

std::optional<secure_vector<uint8_t>> kemri_try_decrypt(std::span<const uint8_t> ori_body,
                                                        const Private_Key& key,
                                                        const X509_Certificate& cert,
                                                        RandomNumberGenerator& rng) {
   BER_Decoder dec(ori_body, BER_Decoder::Limits::BER());

   OID ori_type;
   dec.decode(ori_type);
   if(ori_type != OID::from_string("CMS.KEMRecipientInfo")) {
      // An unknown OtherRecipientInfo type; skip this recipient
      dec.discard_remaining();
      return std::nullopt;
   }

   size_t version = 0;
   SignerIdentifier rid;
   AlgorithmIdentifier kem_alg;
   std::vector<uint8_t> kemct;
   AlgorithmIdentifier kdf_alg;
   size_t kek_len = 0;
   std::optional<std::vector<uint8_t>> ukm;
   AlgorithmIdentifier wrap_alg;
   std::vector<uint8_t> encrypted_key;

   BER_Decoder kemri = dec.start_sequence();
   kemri.decode(version)
      .decode(rid)
      .decode(kem_alg)
      .decode(kemct, ASN1_Type::OctetString)
      .decode(kdf_alg)
      .decode(kek_len);
   if(kemri.peek_next_object().is_a(ASN1_Type(0), ASN1_Class::ExplicitContextSpecific)) {
      std::vector<uint8_t> ukm_bytes;
      BER_Decoder ukm_dec = kemri.start_explicit_context_specific(0);
      ukm_dec.decode(ukm_bytes, ASN1_Type::OctetString);
      ukm_dec.end_cons();
      ukm = std::move(ukm_bytes);
   }
   kemri.decode(wrap_alg).decode(encrypted_key, ASN1_Type::OctetString);
   kemri.end_cons();
   dec.verify_end();

   // RFC 9629 3: "version is the syntax version number. The version MUST be 0."
   if(version != 0) {
      throw Decoding_Error("CMS KEMRecipientInfo has invalid version");
   }

   if(!rid.matches(cert)) {
      return std::nullopt;
   }

   const std::string kem_name = kem_alg.oid().human_name_or_empty();
   if(!is_ml_kem_oid_name(kem_name) || !kem_alg.parameters_are_empty()) {
      throw Decoding_Error(fmt("CMS KEMRecipientInfo with unsupported KEM {}", kem_alg.oid()));
   }
   if(kem_alg.oid() != key.object_identifier()) {
      throw Decryption_Error("KEMRecipientInfo KEM algorithm does not match the given key");
   }

   // RFC 8619 2: "the parameters component of that type SHALL be absent"
   const std::string kdf_name = kdf_for_oid(kdf_alg.oid());
   if(!kdf_alg.parameters_are_empty()) {
      throw Decoding_Error("CMS KEMRecipientInfo KDF has unexpected parameters");
   }

   const std::string wrap_cipher = block_cipher_for_wrap(wrap_alg.oid());
   if(!wrap_alg.parameters_are_empty()) {
      throw Decoding_Error("CMS KEMRecipientInfo key wrap has unexpected parameters");
   }

   auto aes = BlockCipher::create_or_throw(wrap_cipher);

   /*
   * RFC 9629 3: "Implementations MUST confirm that the value provided
   * is consistent with the key-encryption algorithm identified in the
   * wrap field"
   */
   if(kek_len != aes->key_spec().maximum_keylength()) {
      throw Decoding_Error("CMS KEMRecipientInfo kekLength does not match the key wrap algorithm");
   }

   PK_KEM_Decryptor kem(key, rng, "Raw");
   if(kemct.size() != kem.encapsulated_key_length()) {
      throw Decryption_Error("KEMRecipientInfo ciphertext has invalid length");
   }
   const auto shared_secret = kem.decrypt(std::span{kemct});

   const auto kek = derive_kek(kdf_name, shared_secret, kek_len, wrap_alg, ukm);
   aes->set_key(kek);

   try {
      return nist_key_unwrap(encrypted_key.data(), encrypted_key.size(), *aes);
   } catch(Invalid_Authentication_Tag&) {
      throw Decryption_Error("KEMRecipientInfo CEK unwrap failed");
   } catch(Invalid_Argument&) {
      throw Decryption_Error("KEMRecipientInfo encryptedKey is malformed");
   }
}

}  // namespace Botan::CMS

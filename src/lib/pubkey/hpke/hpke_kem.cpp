/*
* HPKE KEMs
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hpke_kem.h>

#include <botan/ec_apoint.h>
#include <botan/ec_group.h>
#include <botan/ec_scalar.h>
#include <botan/ecdh.h>
#include <botan/exceptn.h>
#include <botan/mac.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/hkdf.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mem_utils.h>
#include <algorithm>
#include <optional>
#include <type_traits>

#if defined(BOTAN_HAS_X25519)
   #include <botan/x25519.h>
#endif

#if defined(BOTAN_HAS_X448)
   #include <botan/x448.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/ecdsa.h>
#endif

namespace Botan::HPKE {

namespace {

std::string kem_name(KEM_Id kem) {
   return kem.to_string().value_or(std::to_string(kem.wire_code()));
}

}  // namespace

secure_vector<uint8_t> labeled_extract(std::string_view hash,
                                       std::span<const uint8_t> suite_id,
                                       std::span<const uint8_t> salt,
                                       std::string_view label,
                                       std::span<const uint8_t> ikm) {
   // See RFC 9180 Section 4
   auto prf = MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", hash));
   const size_t nh = prf->output_length();
   const HKDF_Extract kdf(std::move(prf));

   const auto labeled_ikm = concat<secure_vector<uint8_t>>(
      as_span_of_bytes(std::string_view("HPKE-v1")), suite_id, as_span_of_bytes(label), ikm);

   return kdf.derive_key<secure_vector<uint8_t>>(nh, labeled_ikm, salt, std::span<const uint8_t>{});
}

secure_vector<uint8_t> labeled_expand(std::string_view hash,
                                      std::span<const uint8_t> suite_id,
                                      std::span<const uint8_t> prk,
                                      std::string_view label,
                                      std::span<const uint8_t> info,
                                      size_t length) {
   // See RFC 9180 Section 4
   BOTAN_ARG_CHECK(length <= 0xFFFF, "HPKE LabeledExpand output length too large");

   if(length == 0) {
      return {};
   }

   const HKDF_Expand kdf(MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", hash)));

   const auto labeled_info = concat<std::vector<uint8_t>>(store_be(static_cast<uint16_t>(length)),
                                                          as_span_of_bytes(std::string_view("HPKE-v1")),
                                                          suite_id,
                                                          as_span_of_bytes(label),
                                                          info);

   return kdf.derive_key<secure_vector<uint8_t>>(length, prk, std::span<const uint8_t>{}, labeled_info);
}

KEM_Ops::Encapsulation KEM_Ops::auth_encap(const Botan::Public_Key& /*pkR*/,
                                           const Botan::Private_Key& /*skS*/,
                                           RandomNumberGenerator& /*rng*/) const {
   // See RFC 9180 Section 7.1.5
   throw Invalid_Argument(fmt("HPKE KEM {} does not support the Auth modes", kem_name(kem_id())));
}

secure_vector<uint8_t> KEM_Ops::auth_decap(std::span<const uint8_t> /*enc*/,
                                           const Botan::Private_Key& /*skR*/,
                                           const Botan::Public_Key& /*pkS*/,
                                           RandomNumberGenerator& /*rng*/) const {
   // See RFC 9180 Section 7.1.5
   throw Invalid_Argument(fmt("HPKE KEM {} does not support the Auth modes", kem_name(kem_id())));
}

KEM_Ops::Encapsulation KEM_Ops::encap_with_ephemeral(const Botan::Public_Key& /*pkR*/,
                                                     const Botan::Private_Key& /*skE*/,
                                                     RandomNumberGenerator& /*rng*/) const {
   throw Not_Implemented(fmt("HPKE KEM {} does not support deterministic encapsulation", kem_name(kem_id())));
}

KEM_Ops::Encapsulation KEM_Ops::auth_encap_with_ephemeral(const Botan::Public_Key& /*pkR*/,
                                                          const Botan::Private_Key& /*skS*/,
                                                          const Botan::Private_Key& /*skE*/,
                                                          RandomNumberGenerator& /*rng*/) const {
   throw Not_Implemented(fmt("HPKE KEM {} does not support deterministic encapsulation", kem_name(kem_id())));
}

namespace {

std::vector<uint8_t> kem_suite_id(KEM_Id kem) {
   // See RFC 9180 Section 4.1
   const uint16_t code = kem.wire_code();
   return {'K', 'E', 'M', static_cast<uint8_t>(code >> 8), static_cast<uint8_t>(code & 0xFF)};
}

enum class DH_Group : uint8_t { P256, P384, P521, X25519, X448 };

/// The private or public key type of an algorithm
template <bool is_private, typename PrivateT, typename PublicT>
using select_key_t = std::conditional_t<is_private, PrivateT, PublicT>;

/*
* Scalar clamping as in RFC 7748 Section 5 (decodeScalar25519 and
* decodeScalar448). RFC 9180 Section 7.1.2 requires SerializePrivateKey to
* clamp its output and DeserializePrivateKey to clamp its input.
*/
void clamp_scalar(DH_Group group, std::span<uint8_t> sk) {
   if(group == DH_Group::X25519) {
      BOTAN_ASSERT_NOMSG(sk.size() == 32);
      sk[0] &= 248;
      sk[31] &= 127;
      sk[31] |= 64;
   } else if(group == DH_Group::X448) {
      BOTAN_ASSERT_NOMSG(sk.size() == 56);
      sk[0] &= 252;
      sk[55] |= 128;
   }
}

class DHKEM final : public KEM_Ops {
   public:
      DHKEM(KEM_Id id, DH_Group group, std::string_view hash, std::string_view curve, uint8_t candidate_mask) :
            KEM_Ops(id),
            m_group(group),
            m_hash(hash),
            m_nh(MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", hash))->output_length()),
            m_candidate_mask(candidate_mask),
            m_suite_id(kem_suite_id(id)) {
         if(!curve.empty()) {
            m_ec_group = EC_Group::from_name(curve);
         }
      }

      // See RFC 9180 Section 7.1
      bool supports_auth() const override { return true; }

      Encapsulation encap(const Botan::Public_Key& pkR, RandomNumberGenerator& rng) const override {
         // See RFC 9180 Section 4.1
         const auto skE = generate_key(rng);
         return encap_impl(pkR, *skE, rng);
      }

      Encapsulation encap_with_ephemeral(const Botan::Public_Key& pkR,
                                         const Botan::Private_Key& skE,
                                         RandomNumberGenerator& rng) const override {
         BOTAN_ARG_CHECK(is_dhkem_private_key(skE), "Ephemeral key does not match the KEM");
         return encap_impl(pkR, skE, rng);
      }

      secure_vector<uint8_t> decap(std::span<const uint8_t> enc,
                                   const Botan::Private_Key& skR,
                                   RandomNumberGenerator& rng) const override {
         // See RFC 9180 Section 4.1
         check_public_encoding(enc);

         const auto pkRm = serialize_public(skR);
         const auto dh_value = dh(skR, enc, rng);
         const auto kem_context = concat<std::vector<uint8_t>>(enc, pkRm);
         return extract_and_expand(dh_value, kem_context);
      }

      Encapsulation auth_encap(const Botan::Public_Key& pkR,
                               const Botan::Private_Key& skS,
                               RandomNumberGenerator& rng) const override {
         // See RFC 9180 Section 4.1
         const auto skE = generate_key(rng);
         return auth_encap_impl(pkR, skS, *skE, rng);
      }

      Encapsulation auth_encap_with_ephemeral(const Botan::Public_Key& pkR,
                                              const Botan::Private_Key& skS,
                                              const Botan::Private_Key& skE,
                                              RandomNumberGenerator& rng) const override {
         BOTAN_ARG_CHECK(is_dhkem_private_key(skE), "Ephemeral key does not match the KEM");
         return auth_encap_impl(pkR, skS, skE, rng);
      }

      secure_vector<uint8_t> auth_decap(std::span<const uint8_t> enc,
                                        const Botan::Private_Key& skR,
                                        const Botan::Public_Key& pkS,
                                        RandomNumberGenerator& rng) const override {
         // See RFC 9180 Section 4.1
         check_public_encoding(enc);

         const auto pkRm = serialize_public(skR);
         const auto pkSm = serialize_public(pkS);

         const auto dh_value = concat<secure_vector<uint8_t>>(dh(skR, enc, rng), dh(skR, pkSm, rng));

         const auto kem_context = concat<std::vector<uint8_t>>(enc, pkRm, pkSm);
         return extract_and_expand(dh_value, kem_context);
      }

      std::unique_ptr<Botan::Private_Key> generate_key(RandomNumberGenerator& rng) const override {
         // See RFC 9180 Section 4
         return this->derive_key_pair(rng.random_vec(kem_id().private_key_length()));
      }

      std::unique_ptr<Botan::Private_Key> derive_key_pair(std::span<const uint8_t> ikm) const override {
         // See RFC 9180 Section 7.1.3
         const size_t nsk = kem_id().private_key_length();
         // The extract step caps usable ikm entropy at the hash length, and MLS
         // (RFC 9420 Section 7.4) derives P-521 key pairs from 64 byte node secrets
         BOTAN_ARG_CHECK(ikm.size() >= std::min(nsk, m_nh), "HPKE DeriveKeyPair ikm too short");

         const auto dkp_prk = labeled_extract(m_hash, m_suite_id, {}, "dkp_prk", ikm);

         switch(m_group) {
#if defined(BOTAN_HAS_X25519)
            case DH_Group::X25519: {
               auto sk = labeled_expand(m_hash, m_suite_id, dkp_prk, "sk", {}, nsk);
               clamp_scalar(m_group, sk);
               return std::make_unique<X25519_PrivateKey>(sk);
            }
#endif
#if defined(BOTAN_HAS_X448)
            case DH_Group::X448: {
               auto sk = labeled_expand(m_hash, m_suite_id, dkp_prk, "sk", {}, nsk);
               clamp_scalar(m_group, sk);
               return std::make_unique<X448_PrivateKey>(sk);
            }
#endif
            case DH_Group::P256:
            case DH_Group::P384:
            case DH_Group::P521: {
               const auto& group = ec_group();
               for(uint16_t counter = 0; counter != 256; ++counter) {
                  const std::array<uint8_t, 1> counter_octet{static_cast<uint8_t>(counter)};
                  auto candidate = labeled_expand(m_hash, m_suite_id, dkp_prk, "candidate", counter_octet, nsk);
                  candidate[0] &= m_candidate_mask;

                  if(const auto scalar = EC_Scalar::deserialize(group, candidate);
                     scalar.has_value() && scalar->is_nonzero()) {
                     return std::make_unique<ECDH_PrivateKey>(group, *scalar);
                  }
               }
               // Probability ~2^-256 per candidate for the supported curves
               throw Internal_Error("HPKE DeriveKeyPair rejection sampling failed");
            }
            default:
               throw Not_Implemented("HPKE DHKEM group not available");
         }
      }

      std::unique_ptr<Botan::Public_Key> deserialize_public(std::span<const uint8_t> bytes) const override {
         // See RFC 9180 Section 7.1.1
         check_public_encoding(bytes);

         switch(m_group) {
#if defined(BOTAN_HAS_X25519)
            case DH_Group::X25519:
               return std::make_unique<X25519_PublicKey>(bytes);
#endif
#if defined(BOTAN_HAS_X448)
            case DH_Group::X448:
               return std::make_unique<X448_PublicKey>(bytes);
#endif
            case DH_Group::P256:
            case DH_Group::P384:
            case DH_Group::P521: {
               const auto& group = ec_group();
               // See RFC 9180 Section 7.1.4
               if(const auto point = EC_AffinePoint::deserialize(group, bytes)) {
                  return std::make_unique<ECDH_PublicKey>(group, *point);
               }
               throw Decoding_Error("HPKE DHKEM public key is not a valid point");
            }
            default:
               throw Not_Implemented("HPKE DHKEM group not available");
         }
      }

      std::unique_ptr<Botan::Private_Key> deserialize_private(std::span<const uint8_t> bytes) const override {
         // See RFC 9180 Section 7.1.2
         if(bytes.size() != kem_id().private_key_length()) {
            throw Decoding_Error(fmt("Invalid private key length for HPKE KEM {}", kem_name(kem_id())));
         }

         switch(m_group) {
#if defined(BOTAN_HAS_X25519)
            case DH_Group::X25519: {
               secure_vector<uint8_t> sk(bytes.begin(), bytes.end());
               clamp_scalar(m_group, sk);
               return std::make_unique<X25519_PrivateKey>(sk);
            }
#endif
#if defined(BOTAN_HAS_X448)
            case DH_Group::X448: {
               secure_vector<uint8_t> sk(bytes.begin(), bytes.end());
               clamp_scalar(m_group, sk);
               return std::make_unique<X448_PrivateKey>(sk);
            }
#endif
            case DH_Group::P256:
            case DH_Group::P384:
            case DH_Group::P521: {
               const auto& group = ec_group();
               if(const auto scalar = EC_Scalar::deserialize(group, bytes);
                  scalar.has_value() && scalar->is_nonzero()) {
                  return std::make_unique<ECDH_PrivateKey>(group, *scalar);
               }
               throw Decoding_Error("HPKE DHKEM private key is out of range");
            }
            default:
               throw Not_Implemented("HPKE DHKEM group not available");
         }
      }

      std::vector<uint8_t> serialize_public(const Botan::Public_Key& key) const override {
         // See RFC 9180 Section 7.1.1
         if(const auto* ecdh = dynamic_cast<const ECDH_PublicKey*>(&key)) {
            // HPKE requires uncompressed encoding for NIST curves
            return ecdh->public_value(EC_Point_Format::Uncompressed);
         }
         auto bytes = key.raw_public_key_bits();
         BOTAN_ASSERT_NOMSG(bytes.size() == kem_id().public_key_length());
         return bytes;
      }

      secure_vector<uint8_t> serialize_private(const Botan::Private_Key& key) const override {
         // See RFC 9180 Section 7.1.2
         auto bytes = key.raw_private_key_bits();
         BOTAN_ASSERT_NOMSG(bytes.size() == kem_id().private_key_length());
         // Keys adopted via from_key may hold an unclamped scalar
         clamp_scalar(m_group, bytes);
         return bytes;
      }

      std::unique_ptr<Botan::Public_Key> adopt_public(std::unique_ptr<Botan::Public_Key> key) const override {
         return adopt_key(std::move(key));
      }

      std::unique_ptr<Botan::Private_Key> adopt_private(std::unique_ptr<Botan::Private_Key> key) const override {
         return adopt_key(std::move(key));
      }

   private:
      /*
      * Accept a key if its type matches this KEM's group. KeyT is either
      * Botan::Public_Key or Botan::Private_Key, and selects which of the
      * algorithm's key types is required.
      */
      template <typename KeyT>
      std::unique_ptr<KeyT> adopt_key(std::unique_ptr<KeyT> key) const {
         constexpr bool is_private = std::is_same_v<KeyT, Botan::Private_Key>;

         switch(m_group) {
#if defined(BOTAN_HAS_X25519)
            case DH_Group::X25519:
               if(dynamic_cast<const select_key_t<is_private, X25519_PrivateKey, X25519_PublicKey>*>(key.get()) !=
                  nullptr) {
                  return key;
               }
               break;
#endif
#if defined(BOTAN_HAS_X448)
            case DH_Group::X448:
               if(dynamic_cast<const select_key_t<is_private, X448_PrivateKey, X448_PublicKey>*>(key.get()) !=
                  nullptr) {
                  return key;
               }
               break;
#endif
            case DH_Group::P256:
            case DH_Group::P384:
            case DH_Group::P521:
               if(const auto* ecdh =
                     dynamic_cast<const select_key_t<is_private, ECDH_PrivateKey, ECDH_PublicKey>*>(key.get())) {
                  check_ec_group(ecdh->domain());
                  return key;
               }
#if defined(BOTAN_HAS_ECDSA)
               /*
               * Keys with the id-ecPublicKey OID, as found in X.509 and PKCS
               * #8, load as ECDSA keys; RFC 3279 Section 2.3.5 allows using that
               * OID for ECDH, so accept ECDSA and convert.
               */
               if(const auto* ecdsa =
                     dynamic_cast<const select_key_t<is_private, ECDSA_PrivateKey, ECDSA_PublicKey>*>(key.get())) {
                  check_ec_group(ecdsa->domain());
                  if constexpr(is_private) {
                     return std::make_unique<ECDH_PrivateKey>(ec_group(), ecdsa->_private_key());
                  } else {
                     return std::make_unique<ECDH_PublicKey>(ec_group(), ecdsa->_public_ec_point());
                  }
               }
#endif
               break;
            default:
               break;
         }

         throw Invalid_Argument(
            fmt("Key of type {} cannot be used with HPKE KEM {}", key->algo_name(), kem_name(kem_id())));
      }

      const EC_Group& ec_group() const {
         BOTAN_ASSERT_NOMSG(m_ec_group.has_value());
         return *m_ec_group;
      }

      void check_ec_group(const EC_Group& group) const {
         if(group != ec_group()) {
            throw Invalid_Argument(fmt("EC key on curve {} cannot be used with HPKE KEM {}",
                                       group.get_curve_oid().to_formatted_string(),
                                       kem_name(kem_id())));
         }
      }

      /// True if the key is of the type this KEM's operations use directly
      bool is_dhkem_private_key(const Botan::Private_Key& key) const {
         switch(m_group) {
#if defined(BOTAN_HAS_X25519)
            case DH_Group::X25519:
               return dynamic_cast<const X25519_PrivateKey*>(&key) != nullptr;
#endif
#if defined(BOTAN_HAS_X448)
            case DH_Group::X448:
               return dynamic_cast<const X448_PrivateKey*>(&key) != nullptr;
#endif
            case DH_Group::P256:
            case DH_Group::P384:
            case DH_Group::P521: {
               const auto* ecdh = dynamic_cast<const ECDH_PrivateKey*>(&key);
               return ecdh != nullptr && ecdh->domain() == ec_group();
            }
            default:
               return false;
         }
      }

      bool is_nist_curve() const {
         return m_group == DH_Group::P256 || m_group == DH_Group::P384 || m_group == DH_Group::P521;
      }

      /*
      * Checks the length of a serialized public key, and for the NIST curves
      * that it uses the uncompressed encoding (RFC 9180 Section 7.1.1). Point
      * validation is left to deserialize_public or the key agreement.
      */
      void check_public_encoding(std::span<const uint8_t> bytes) const {
         if(bytes.size() != kem_id().public_key_length()) {
            throw Decoding_Error(fmt("Invalid public key length for HPKE KEM {}", kem_name(kem_id())));
         }
         if(is_nist_curve() && bytes[0] != 0x04) {
            throw Decoding_Error("HPKE requires uncompressed EC point encoding");
         }
      }

      Encapsulation encap_impl(const Botan::Public_Key& pkR,
                               const Botan::Private_Key& skE,
                               RandomNumberGenerator& rng) const {
         // See RFC 9180 Section 4.1
         const auto pkRm = serialize_public(pkR);
         const auto dh_value = dh(skE, pkRm, rng);

         auto enc = serialize_public(skE);
         const auto kem_context = concat<std::vector<uint8_t>>(enc, pkRm);
         auto shared_secret = extract_and_expand(dh_value, kem_context);
         return {std::move(enc), std::move(shared_secret)};
      }

      Encapsulation auth_encap_impl(const Botan::Public_Key& pkR,
                                    const Botan::Private_Key& skS,
                                    const Botan::Private_Key& skE,
                                    RandomNumberGenerator& rng) const {
         // See RFC 9180 Section 4.1
         const auto pkRm = serialize_public(pkR);
         const auto pkSm = serialize_public(skS);
         auto enc = serialize_public(skE);

         const auto dh_value = concat<secure_vector<uint8_t>>(dh(skE, pkRm, rng), dh(skS, pkRm, rng));

         const auto kem_context = concat<std::vector<uint8_t>>(enc, pkRm, pkSm);
         auto shared_secret = extract_and_expand(dh_value, kem_context);
         return {std::move(enc), std::move(shared_secret)};
      }

      /*
      * The key agreement operations perform the peer key validation that
      * RFC 9180 Section 7.1.4 requires: ECDH rejects encodings that are not
      * a point on the curve, or are the identity, with Decoding_Error, while
      * X25519 and X448 reject low order points by checking for an all-zero
      * shared secret (RFC 7748 Sections 6.1 and 6.2), throwing Invalid_Argument.
      */
      secure_vector<uint8_t> dh(const Botan::Private_Key& sk,
                                std::span<const uint8_t> peer,
                                RandomNumberGenerator& rng) const {
         // See RFC 9180 Section 4.1
         const PK_Key_Agreement ka(sk, rng, "Raw");
         return ka.derive_key(0, peer).bits_of();
      }

      secure_vector<uint8_t> extract_and_expand(std::span<const uint8_t> dh_value,
                                                std::span<const uint8_t> kem_context) const {
         // See RFC 9180 Section 4.1
         const auto eae_prk = labeled_extract(m_hash, m_suite_id, {}, "eae_prk", dh_value);
         return labeled_expand(
            m_hash, m_suite_id, eae_prk, "shared_secret", kem_context, kem_id().shared_secret_length());
      }

      DH_Group m_group;
      std::string m_hash;
      size_t m_nh;
      uint8_t m_candidate_mask;
      std::vector<uint8_t> m_suite_id;
      std::optional<EC_Group> m_ec_group;
};

bool hmac_available(std::string_view hash) {
   return MessageAuthenticationCode::create(fmt("HMAC({})", hash)) != nullptr;
}

}  // namespace

std::unique_ptr<const KEM_Ops> KEM_Ops::create(KEM_Id kem) {
   // See RFC 9180 Sections 7.1 and 7.1.3
   switch(kem.code()) {
      case KEM_Code::DHKEM_P256:
         if(EC_Group::supports_named_group("secp256r1") && hmac_available("SHA-256")) {
            return std::make_unique<DHKEM>(kem, DH_Group::P256, "SHA-256", "secp256r1", 0xFF);
         }
         break;

      case KEM_Code::DHKEM_P384:
         if(EC_Group::supports_named_group("secp384r1") && hmac_available("SHA-384")) {
            return std::make_unique<DHKEM>(kem, DH_Group::P384, "SHA-384", "secp384r1", 0xFF);
         }
         break;

      case KEM_Code::DHKEM_P521:
         if(EC_Group::supports_named_group("secp521r1") && hmac_available("SHA-512")) {
            return std::make_unique<DHKEM>(kem, DH_Group::P521, "SHA-512", "secp521r1", 0x01);
         }
         break;

      case KEM_Code::DHKEM_X25519:
#if defined(BOTAN_HAS_X25519)
         if(hmac_available("SHA-256")) {
            return std::make_unique<DHKEM>(kem, DH_Group::X25519, "SHA-256", "", 0x00);
         }
#endif
         break;

      case KEM_Code::DHKEM_X448:
#if defined(BOTAN_HAS_X448)
         if(hmac_available("SHA-512")) {
            return std::make_unique<DHKEM>(kem, DH_Group::X448, "SHA-512", "", 0x00);
         }
#endif
         break;

      default:
         break;
   }

   throw Not_Implemented(fmt("HPKE KEM {} is not available in this build", kem_name(kem)));
}

}  // namespace Botan::HPKE

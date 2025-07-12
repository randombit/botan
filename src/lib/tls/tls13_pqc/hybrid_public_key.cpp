/**
* Composite key pair that exposes the Public/Private key API but combines
* multiple key agreement schemes into a hybrid algorithm.
*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hybrid_public_key.h>

#include <botan/ec_group.h>
#include <botan/pk_algs.h>

#include <botan/internal/fmt.h>
#include <botan/internal/hybrid_kem_ops.h>
#include <botan/internal/kex_to_kem_adapter.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/stl_util.h>

namespace Botan::TLS {

namespace {

std::vector<std::pair<std::string, std::string>> algorithm_specs_for_group(Group_Params group) {
   BOTAN_ARG_CHECK(group.is_pqc_hybrid(), "Group is not hybrid");

   switch(group.code()) {
      // draft-kwiatkowski-tls-ecdhe-mlkem-02 Section 3
      //
      //    NIST's special publication 800-56Cr2 approves the usage of HKDF with
      //    two distinct shared secrets, with the condition that the first one
      //    is computed by a FIPS-approved key-establishment scheme.  FIPS also
      //    requires a certified implementation of the scheme, which will remain
      //    more ubiqutous for secp256r1 in the coming years.
      //
      //    For this reason we put the ML-KEM-768 shared secret first in
      //    X25519MLKEM768, and the secp256r1 shared secret first in
      //    SecP256r1MLKEM768.
      case Group_Params::HYBRID_X25519_ML_KEM_768:
         return {{"ML-KEM", "ML-KEM-768"}, {"X25519", "X25519"}};
      case Group_Params::HYBRID_SECP256R1_ML_KEM_768:
         return {{"ECDH", "secp256r1"}, {"ML-KEM", "ML-KEM-768"}};
      case Group_Params::HYBRID_SECP384R1_ML_KEM_1024:
         return {{"ECDH", "secp384r1"}, {"ML-KEM", "ML-KEM-1024"}};

      case Group_Params::HYBRID_X25519_eFRODOKEM_640_SHAKE_OQS:
         return {{"X25519", "X25519"}, {"FrodoKEM", "eFrodoKEM-640-SHAKE"}};
      case Group_Params::HYBRID_X25519_eFRODOKEM_640_AES_OQS:
         return {{"X25519", "X25519"}, {"FrodoKEM", "eFrodoKEM-640-AES"}};
      case Group_Params::HYBRID_X448_eFRODOKEM_976_SHAKE_OQS:
         return {{"X448", "X448"}, {"FrodoKEM", "eFrodoKEM-976-SHAKE"}};
      case Group_Params::HYBRID_X448_eFRODOKEM_976_AES_OQS:
         return {{"X448", "X448"}, {"FrodoKEM", "eFrodoKEM-976-AES"}};

      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_SHAKE_OQS:
         return {{"ECDH", "secp256r1"}, {"FrodoKEM", "eFrodoKEM-640-SHAKE"}};
      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_AES_OQS:
         return {{"ECDH", "secp256r1"}, {"FrodoKEM", "eFrodoKEM-640-AES"}};

      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_SHAKE_OQS:
         return {{"ECDH", "secp384r1"}, {"FrodoKEM", "eFrodoKEM-976-SHAKE"}};
      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_AES_OQS:
         return {{"ECDH", "secp384r1"}, {"FrodoKEM", "eFrodoKEM-976-AES"}};

      case Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_SHAKE_OQS:
         return {{"ECDH", "secp521r1"}, {"FrodoKEM", "eFrodoKEM-1344-SHAKE"}};
      case Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_AES_OQS:
         return {{"ECDH", "secp521r1"}, {"FrodoKEM", "eFrodoKEM-1344-AES"}};

      default:
         return {};
   }
}

std::vector<AlgorithmIdentifier> algorithm_identifiers_for_group(Group_Params group) {
   BOTAN_ASSERT_NOMSG(group.is_pqc_hybrid());

   const auto specs = algorithm_specs_for_group(group);
   std::vector<AlgorithmIdentifier> result;
   result.reserve(specs.size());

   // This maps the string-based algorithm specs hard-coded above to OID-based
   // AlgorithmIdentifier objects. The mapping is needed because
   // load_public_key() depends on those while create_private_key() requires the
   // strong-based spec.
   //
   // TODO: This is inconvenient, confusing and error-prone. Find a better way
   //       to load arbitrary public keys.
   for(const auto& spec : specs) {
      if(spec.first == "ECDH") {
         result.push_back(AlgorithmIdentifier("ECDH", EC_Group::from_name(spec.second).DER_encode()));
      } else {
         result.push_back(AlgorithmIdentifier(spec.second, AlgorithmIdentifier::USE_EMPTY_PARAM));
      }
   }

   return result;
}

std::vector<size_t> public_key_lengths_for_group(Group_Params group) {
   BOTAN_ASSERT_NOMSG(group.is_pqc_hybrid());

   // This duplicates information of the algorithm internals.
   //
   // TODO: Find a way to expose important algorithm constants globally
   //       in the library, to avoid violating the DRY principle.
   switch(group.code()) {
      case Group_Params::HYBRID_X25519_ML_KEM_768:
         return {1184, 32};
      case Group_Params::HYBRID_SECP256R1_ML_KEM_768:
         return {65, 1184};
      case Group_Params::HYBRID_SECP384R1_ML_KEM_1024:
         return {97, 1568};

      case Group_Params::HYBRID_X25519_eFRODOKEM_640_SHAKE_OQS:
         return {32, 9616};
      case Group_Params::HYBRID_X25519_eFRODOKEM_640_AES_OQS:
         return {32, 9616};
      case Group_Params::HYBRID_X448_eFRODOKEM_976_SHAKE_OQS:
         return {56, 15632};
      case Group_Params::HYBRID_X448_eFRODOKEM_976_AES_OQS:
         return {56, 15632};

      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_SHAKE_OQS:
         return {65, 9616};
      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_AES_OQS:
         return {65, 9616};

      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_SHAKE_OQS:
         return {97, 15632};
      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_AES_OQS:
         return {97, 15632};

      case Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_SHAKE_OQS:
         return {133, 21520};
      case Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_AES_OQS:
         return {133, 21520};

      default:
         return {};
   }
}

std::vector<std::unique_ptr<Public_Key>> convert_kex_to_kem_pks(std::vector<std::unique_ptr<Public_Key>> pks) {
   std::vector<std::unique_ptr<Public_Key>> result;
   std::transform(pks.begin(), pks.end(), std::back_inserter(result), [](auto& key) -> std::unique_ptr<Public_Key> {
      BOTAN_ARG_CHECK(key != nullptr, "Public key list contains a nullptr");
      if(key->supports_operation(PublicKeyOperation::KeyAgreement) &&
         !key->supports_operation(PublicKeyOperation::KeyEncapsulation)) {
         return std::make_unique<KEX_to_KEM_Adapter_PublicKey>(std::move(key));
      } else {
         return std::move(key);
      }
   });
   return result;
}

std::vector<std::unique_ptr<Private_Key>> convert_kex_to_kem_sks(std::vector<std::unique_ptr<Private_Key>> sks) {
   std::vector<std::unique_ptr<Private_Key>> result;
   std::transform(sks.begin(), sks.end(), std::back_inserter(result), [](auto& key) -> std::unique_ptr<Private_Key> {
      BOTAN_ARG_CHECK(key != nullptr, "Private key list contains a nullptr");
      if(key->supports_operation(PublicKeyOperation::KeyAgreement) &&
         !key->supports_operation(PublicKeyOperation::KeyEncapsulation)) {
         auto* ka_key = dynamic_cast<PK_Key_Agreement_Key*>(key.get());
         BOTAN_ASSERT_NONNULL(ka_key);
         (void)key.release();
         return std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(std::unique_ptr<PK_Key_Agreement_Key>(ka_key));
      } else {
         return std::move(key);
      }
   });
   return result;
}

template <typename KEM_Operation>
void concat_secret_combiner(KEM_Operation& op,
                            std::span<uint8_t> out_shared_secret,
                            const std::vector<secure_vector<uint8_t>>& shared_secrets,
                            size_t desired_shared_key_len) {
   BOTAN_ARG_CHECK(out_shared_secret.size() == op.shared_key_length(desired_shared_key_len),
                   "Invalid output buffer size");

   BufferStuffer shared_secret_stuffer(out_shared_secret);
   for(const auto& ss : shared_secrets) {
      shared_secret_stuffer.append(ss);
   }
   BOTAN_ASSERT_NOMSG(shared_secret_stuffer.full());
}

template <typename KEM_Operation>
size_t concat_shared_key_length(const std::vector<KEM_Operation>& operation) {
   return reduce(
      operation, size_t(0), [](size_t acc, const auto& op) { return acc + op.shared_key_length(0 /*no KDF*/); });
}

/// Encryptor that simply concatenates the multiple shared secrets
class Hybrid_TLS_KEM_Encryptor final : public KEM_Encryption_with_Combiner {
   public:
      Hybrid_TLS_KEM_Encryptor(const std::vector<std::unique_ptr<Public_Key>>& public_keys, std::string_view provider) :
            KEM_Encryption_with_Combiner(public_keys, provider) {}

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const std::vector<secure_vector<uint8_t>>& shared_secrets,
                                  const std::vector<std::vector<uint8_t>>& /*ciphertexts*/,
                                  size_t desired_shared_key_len,
                                  std::span<const uint8_t> /*salt*/) override {
         concat_secret_combiner(*this, out_shared_secret, shared_secrets, desired_shared_key_len);
      }

      size_t shared_key_length(size_t /*desired_shared_key_len*/) const override {
         return concat_shared_key_length(encryptors());
      }
};

/// Decryptor that simply concatenates the multiple shared secrets
class Hybrid_TLS_KEM_Decryptor final : public KEM_Decryption_with_Combiner {
   public:
      Hybrid_TLS_KEM_Decryptor(const std::vector<std::unique_ptr<Private_Key>>& private_keys,
                               RandomNumberGenerator& rng,
                               const std::string_view provider) :
            KEM_Decryption_with_Combiner(private_keys, rng, provider) {}

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const std::vector<secure_vector<uint8_t>>& shared_secrets,
                                  const std::vector<std::vector<uint8_t>>& /*ciphertexts*/,
                                  size_t desired_shared_key_len,
                                  std::span<const uint8_t> /*salt*/) override {
         concat_secret_combiner(*this, out_shared_secret, shared_secrets, desired_shared_key_len);
      }

      size_t shared_key_length(size_t /*desired_shared_key_len*/) const override {
         return concat_shared_key_length(decryptors());
      }
};

}  // namespace

std::unique_ptr<Hybrid_KEM_PublicKey> Hybrid_KEM_PublicKey::load_for_group(
   Group_Params group, std::span<const uint8_t> concatenated_public_keys) {
   const auto public_key_lengths = public_key_lengths_for_group(group);
   auto alg_ids = algorithm_identifiers_for_group(group);
   BOTAN_ASSERT_NOMSG(public_key_lengths.size() == alg_ids.size());

   const auto expected_public_keys_length =
      reduce(public_key_lengths, size_t(0), [](size_t acc, size_t len) { return acc + len; });
   if(expected_public_keys_length != concatenated_public_keys.size()) {
      throw Decoding_Error("Concatenated public values have an unexpected length");
   }

   BufferSlicer public_key_slicer(concatenated_public_keys);
   std::vector<std::unique_ptr<Public_Key>> pks;
   pks.reserve(alg_ids.size());
   for(size_t idx = 0; idx < alg_ids.size(); ++idx) {
      pks.emplace_back(load_public_key(alg_ids[idx], public_key_slicer.take(public_key_lengths[idx])));
   }
   BOTAN_ASSERT_NOMSG(public_key_slicer.empty());
   return std::make_unique<Hybrid_KEM_PublicKey>(std::move(pks));
}

Hybrid_KEM_PublicKey::Hybrid_KEM_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks) :
      Hybrid_PublicKey(convert_kex_to_kem_pks(std::move(pks))) {}

Hybrid_KEM_PrivateKey::Hybrid_KEM_PrivateKey(std::vector<std::unique_ptr<Private_Key>> sks) :
      Hybrid_PublicKey(convert_kex_to_kem_pks(extract_public_keys(sks))),
      Hybrid_PrivateKey(convert_kex_to_kem_sks(std::move(sks))) {}

std::string Hybrid_KEM_PublicKey::algo_name() const {
   std::ostringstream algo_name("Hybrid(");
   for(size_t i = 0; i < public_keys().size(); ++i) {
      if(i > 0) {
         algo_name << ",";
      }
      algo_name << public_keys().at(i)->algo_name();
   }
   algo_name << ")";
   return algo_name.str();
}

AlgorithmIdentifier Hybrid_KEM_PublicKey::algorithm_identifier() const {
   throw Botan::Not_Implemented("Hybrid keys don't have an algorithm identifier");
}

std::vector<uint8_t> Hybrid_KEM_PublicKey::public_key_bits() const {
   return raw_public_key_bits();
}

std::vector<uint8_t> Hybrid_KEM_PublicKey::raw_public_key_bits() const {
   // draft-ietf-tls-hybrid-design-06 3.2
   //   The values are directly concatenated, without any additional encoding
   //   or length fields; this assumes that the representation and length of
   //   elements is fixed once the algorithm is fixed.  If concatenation were
   //   to be used with values that are not fixed-length, a length prefix or
   //   other unambiguous encoding must be used to ensure that the composition
   //   of the two values is injective.
   return reduce(public_keys(), std::vector<uint8_t>(), [](auto pkb, const auto& key) {
      return concat(pkb, key->raw_public_key_bits());
   });
}

std::unique_ptr<Private_Key> Hybrid_KEM_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Hybrid_KEM_PrivateKey>(generate_other_sks_from_pks(rng));
}

std::unique_ptr<Botan::PK_Ops::KEM_Encryption> Hybrid_KEM_PublicKey::create_kem_encryption_op(
   std::string_view params, std::string_view provider) const {
   if(params != "Raw" && !params.empty()) {
      throw Botan::Invalid_Argument("Hybrid KEM encryption does not support KDFs");
   }
   return std::make_unique<Hybrid_TLS_KEM_Encryptor>(public_keys(), provider);
}

std::unique_ptr<Hybrid_KEM_PrivateKey> Hybrid_KEM_PrivateKey::generate_from_group(Group_Params group,
                                                                                  RandomNumberGenerator& rng) {
   const auto algo_spec = algorithm_specs_for_group(group);
   std::vector<std::unique_ptr<Private_Key>> private_keys;
   private_keys.reserve(algo_spec.size());
   for(const auto& spec : algo_spec) {
      private_keys.push_back(create_private_key(spec.first, rng, spec.second));
   }
   return std::make_unique<Hybrid_KEM_PrivateKey>(std::move(private_keys));
}

std::unique_ptr<Botan::PK_Ops::KEM_Decryption> Hybrid_KEM_PrivateKey::create_kem_decryption_op(
   RandomNumberGenerator& rng, std::string_view params, std::string_view provider) const {
   if(params != "Raw" && !params.empty()) {
      throw Botan::Invalid_Argument("Hybrid KEM decryption does not support KDFs");
   }
   return std::make_unique<Hybrid_TLS_KEM_Decryptor>(private_keys(), rng, provider);
}

}  // namespace Botan::TLS

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
      case Group_Params::HYBRID_X25519_KYBER_512_R3_OQS:
      case Group_Params::HYBRID_X25519_KYBER_512_R3_CLOUDFLARE:
         return {{"X25519", "X25519"}, {"Kyber", "Kyber-512-r3"}};
      case Group_Params::HYBRID_X25519_KYBER_768_R3_OQS:
         return {{"X25519", "X25519"}, {"Kyber", "Kyber-768-r3"}};
      case Group_Params::HYBRID_X448_KYBER_768_R3_OQS:
         return {{"X448", "X448"}, {"Kyber", "Kyber-768-r3"}};
      case Group_Params::HYBRID_X25519_eFRODOKEM_640_SHAKE_OQS:
         return {{"X25519", "X25519"}, {"FrodoKEM", "eFrodoKEM-640-SHAKE"}};
      case Group_Params::HYBRID_X25519_eFRODOKEM_640_AES_OQS:
         return {{"X25519", "X25519"}, {"FrodoKEM", "eFrodoKEM-640-AES"}};
      case Group_Params::HYBRID_X448_eFRODOKEM_976_SHAKE_OQS:
         return {{"X448", "X448"}, {"FrodoKEM", "eFrodoKEM-976-SHAKE"}};
      case Group_Params::HYBRID_X448_eFRODOKEM_976_AES_OQS:
         return {{"X448", "X448"}, {"FrodoKEM", "eFrodoKEM-976-AES"}};

      case Group_Params::HYBRID_SECP256R1_KYBER_512_R3_OQS:
         return {{"ECDH", "secp256r1"}, {"Kyber", "Kyber-512-r3"}};
      case Group_Params::HYBRID_SECP256R1_KYBER_768_R3_OQS:
         return {{"ECDH", "secp256r1"}, {"Kyber", "Kyber-768-r3"}};
      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_SHAKE_OQS:
         return {{"ECDH", "secp256r1"}, {"FrodoKEM", "eFrodoKEM-640-SHAKE"}};
      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_AES_OQS:
         return {{"ECDH", "secp256r1"}, {"FrodoKEM", "eFrodoKEM-640-AES"}};

      case Group_Params::HYBRID_SECP384R1_KYBER_768_R3_OQS:
         return {{"ECDH", "secp384r1"}, {"Kyber", "Kyber-768-r3"}};
      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_SHAKE_OQS:
         return {{"ECDH", "secp384r1"}, {"FrodoKEM", "eFrodoKEM-976-SHAKE"}};
      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_AES_OQS:
         return {{"ECDH", "secp384r1"}, {"FrodoKEM", "eFrodoKEM-976-AES"}};

      case Group_Params::HYBRID_SECP521R1_KYBER_1024_R3_OQS:
         return {{"ECDH", "secp521r1"}, {"Kyber", "Kyber-1024-r3"}};
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
      result.push_back(AlgorithmIdentifier(spec.second, AlgorithmIdentifier::USE_EMPTY_PARAM));
   }

   return result;
}

std::vector<size_t> public_value_lengths_for_group(Group_Params group) {
   BOTAN_ASSERT_NOMSG(group.is_pqc_hybrid());

   // This duplicates information of the algorithm internals.
   //
   // TODO: Find a way to expose important algorithm constants globally
   //       in the library, to avoid violating the DRY principle.
   switch(group.code()) {
      case Group_Params::HYBRID_X25519_KYBER_512_R3_CLOUDFLARE:
      case Group_Params::HYBRID_X25519_KYBER_512_R3_OQS:
         return {32, 800};
      case Group_Params::HYBRID_X25519_KYBER_768_R3_OQS:
         return {32, 1184};
      case Group_Params::HYBRID_X448_KYBER_768_R3_OQS:
         return {56, 1184};
      case Group_Params::HYBRID_X25519_eFRODOKEM_640_SHAKE_OQS:
         return {32, 9616};
      case Group_Params::HYBRID_X25519_eFRODOKEM_640_AES_OQS:
         return {32, 9616};
      case Group_Params::HYBRID_X448_eFRODOKEM_976_SHAKE_OQS:
         return {56, 15632};
      case Group_Params::HYBRID_X448_eFRODOKEM_976_AES_OQS:
         return {56, 15632};

      case Group_Params::HYBRID_SECP256R1_KYBER_512_R3_OQS:
         return {32, 800};
      case Group_Params::HYBRID_SECP256R1_KYBER_768_R3_OQS:
         return {32, 1184};
      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_SHAKE_OQS:
         return {32, 9616};
      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_AES_OQS:
         return {32, 9616};

      case Group_Params::HYBRID_SECP384R1_KYBER_768_R3_OQS:
         return {48, 1184};
      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_SHAKE_OQS:
         return {48, 15632};
      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_AES_OQS:
         return {48, 15632};

      case Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_SHAKE_OQS:
         return {66, 21520};
      case Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_AES_OQS:
         return {66, 21520};
      case Group_Params::HYBRID_SECP521R1_KYBER_1024_R3_OQS:
         return {66, 1568};

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
         auto ka_key = dynamic_cast<PK_Key_Agreement_Key*>(key.get());
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
   for(size_t idx = 0; idx < shared_secrets.size(); idx++) {
      shared_secret_stuffer.append(shared_secrets.at(idx));
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
   Group_Params group, std::span<const uint8_t> concatenated_public_values) {
   const auto public_value_lengths = public_value_lengths_for_group(group);
   auto alg_ids = algorithm_identifiers_for_group(group);
   BOTAN_ASSERT_NOMSG(public_value_lengths.size() == alg_ids.size());

   const auto expected_public_values_length =
      reduce(public_value_lengths, size_t(0), [](size_t acc, size_t len) { return acc + len; });
   BOTAN_ARG_CHECK(expected_public_values_length == concatenated_public_values.size(),
                   "Concatenated public values have an unexpected length");

   BufferSlicer public_value_slicer(concatenated_public_values);
   std::vector<std::unique_ptr<Public_Key>> pks;
   for(size_t idx = 0; idx < alg_ids.size(); ++idx) {
      pks.emplace_back(load_public_key(alg_ids[idx], public_value_slicer.take(public_value_lengths[idx])));
   }
   BOTAN_ASSERT_NOMSG(public_value_slicer.empty());
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

/**
* Composite key pair that exposes the Public/Private key API but combines
* multiple key agreement schemes into a hybrid algorithm.
*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*     2026 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_hybrid_kem.h>

#include <botan/ec_group.h>
#include <botan/mem_ops.h>
#include <botan/pk_algs.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/hybrid_kem_ops.h>
#include <botan/internal/kex_to_kem_adapter.h>
#include <botan/internal/stl_util.h>

namespace Botan::TLS {

namespace {

struct AlgorithmSpec {
      std::string_view type;
      std::string_view param;
};

using PairOfAlgorithmSpecs = std::pair<AlgorithmSpec, AlgorithmSpec>;
using PairOfAlgorithmIdentifiers = std::pair<AlgorithmIdentifier, AlgorithmIdentifier>;
using PairOfPublicKeyLengths = std::pair<size_t, size_t>;

PairOfAlgorithmSpecs algorithm_specs_for_group(Group_Params group) {
   BOTAN_ARG_CHECK(group.is_pqc_hybrid(), "Group is not hybrid");

   switch(group.code()) {
      // draft-kwiatkowski-tls-ecdhe-mlkem-02 Section 3
      //
      //    NIST's special publication 800-56Cr2 approves the usage of HKDF with
      //    two distinct shared secrets, with the condition that the first one
      //    is computed by a FIPS-approved key-establishment scheme.  FIPS also
      //    requires a certified implementation of the scheme, which will remain
      //    more ubiquitous for secp256r1 in the coming years.
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

PairOfAlgorithmIdentifiers algorithm_identifiers_for_group(Group_Params group) {
   BOTAN_ASSERT_NOMSG(group.is_pqc_hybrid());

   // This maps the string-based algorithm specs hard-coded above to OID-based
   // AlgorithmIdentifier objects. The mapping is needed because
   // load_public_key() depends on those while create_private_key() requires the
   // string-based spec.
   //
   // TODO: This is inconvenient, confusing and error-prone. Find a better way
   //       to load arbitrary public keys.
   auto into_algorithm_identifier = [](const AlgorithmSpec& spec) -> AlgorithmIdentifier {
      if(spec.type == "ECDH") {
         return {"ECDH", EC_Group::from_name(spec.param).DER_encode()};
      } else {
         return {spec.param, AlgorithmIdentifier::USE_EMPTY_PARAM};
      }
   };

   const auto specs = algorithm_specs_for_group(group);
   return {
      into_algorithm_identifier(specs.first),
      into_algorithm_identifier(specs.second),
   };
}

PairOfPublicKeyLengths public_key_lengths_for_group(Group_Params group) {
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
      case Group_Params::HYBRID_X25519_eFRODOKEM_640_AES_OQS:
         return {32, 9616};

      case Group_Params::HYBRID_X448_eFRODOKEM_976_SHAKE_OQS:
      case Group_Params::HYBRID_X448_eFRODOKEM_976_AES_OQS:
         return {56, 15632};

      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_SHAKE_OQS:
      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_AES_OQS:
         return {65, 9616};

      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_SHAKE_OQS:
      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_AES_OQS:
         return {97, 15632};

      case Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_SHAKE_OQS:
      case Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_AES_OQS:
         return {133, 21520};

      default:
         return {};
   }
}

template <typename T>
   requires(std::same_as<T, PK_KEM_Encryptor> || std::same_as<T, PK_KEM_Decryptor>)
size_t combined_shared_secret_length(const std::pair<T, T>& encryptors) {
   constexpr size_t desired_key_length = 0;  // no KDF used, hence zero
   return encryptors.first.shared_key_length(desired_key_length) +
          encryptors.second.shared_key_length(desired_key_length);
}

void concat_shared_secrets(std::span<uint8_t> out_shared_secret, const PairOfSharedSecrets& shared_secrets) {
   BufferStuffer bs(out_shared_secret);
   bs.append(shared_secrets.first);
   bs.append(shared_secrets.second);
   BOTAN_ASSERT_NOMSG(bs.full());
}

/// Encryptor that simply concatenates the multiple shared secrets
class Hybrid_TLS_KEM_Encryptor final : public KEM_Encryption_with_Combiner {
   public:
      using KEM_Encryption_with_Combiner::KEM_Encryption_with_Combiner;

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const PairOfSharedSecrets& shared_secrets,
                                  const PairOfCiphertexts& /*ciphertexts*/,
                                  size_t desired_shared_key_len,
                                  std::span<const uint8_t> /*salt*/) override {
         BOTAN_ARG_CHECK(out_shared_secret.size() == shared_key_length(desired_shared_key_len),
                         "Hybrid_TLS_KEM_Encryptor: Invalid output buffer size");
         concat_shared_secrets(out_shared_secret, shared_secrets);
      }

      size_t shared_key_length(size_t /*desired_shared_key_len*/) const override {
         return combined_shared_secret_length(encryptors());
      }
};

/// Decryptor that simply concatenates the multiple shared secrets
class Hybrid_TLS_KEM_Decryptor final : public KEM_Decryption_with_Combiner {
   public:
      using KEM_Decryption_with_Combiner::KEM_Decryption_with_Combiner;

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const PairOfSharedSecrets& shared_secrets,
                                  const PairOfCiphertexts& /*ciphertexts*/,
                                  size_t desired_shared_key_len,
                                  std::span<const uint8_t> /*salt*/) override {
         BOTAN_ARG_CHECK(out_shared_secret.size() == shared_key_length(desired_shared_key_len),
                         "Hybrid_TLS_KEM_Decryptor: Invalid output buffer size");
         concat_shared_secrets(out_shared_secret, shared_secrets);
      }

      size_t shared_key_length(size_t /*desired_shared_key_len*/) const override {
         return combined_shared_secret_length(decryptors());
      }
};

}  // namespace

std::unique_ptr<Hybrid_TLS_KEM_PublicKey> Hybrid_TLS_KEM_PublicKey::load_for_group(
   Group_Params group, std::span<const uint8_t> concatenated_public_keys) {
   const auto public_key_lengths = public_key_lengths_for_group(group);
   auto alg_ids = algorithm_identifiers_for_group(group);

   const auto expected_public_keys_length = public_key_lengths.first + public_key_lengths.second;
   if(expected_public_keys_length != concatenated_public_keys.size()) {
      throw Decoding_Error("Hybrid_TLS_KEM_PublicKey: Concatenated public values have an unexpected length");
   }

   BufferSlicer public_key_slicer(concatenated_public_keys);
   PairOfPublicKeys public_keys = {
      load_public_key(alg_ids.first, public_key_slicer.take(public_key_lengths.first)),
      load_public_key(alg_ids.second, public_key_slicer.take(public_key_lengths.second)),
   };
   BOTAN_ASSERT_NOMSG(public_key_slicer.empty());

   return std::make_unique<Hybrid_TLS_KEM_PublicKey>(std::move(public_keys));
}

Hybrid_TLS_KEM_PrivateKey::Hybrid_TLS_KEM_PrivateKey(PairOfPrivateKeys private_keys) :
      // Explicitly calling the constructor of the virtually inherited base class
      // Hybrid_KEM_PublicKey to avoid the diamond problem of multiple inheritance.
      // Hybrid_TLS_KEM_PublicKey also calls this constructor, but without effect,
      // because the standard mandates that virtually inherited base classes are
      // only constructed once, by the most derived class: i.e. "here".
      //
      // TODO(Botan4): This is a workaround for the PrivateKey-is-a-PublicKey
      //               design nuisance and may be removed along with it.
      Hybrid_KEM_PublicKey(extract_public_keys(private_keys)),
      Hybrid_TLS_KEM_PublicKey(extract_public_keys(private_keys)),
      Hybrid_KEM_PrivateKey(std::move(private_keys)) {}

std::string Hybrid_TLS_KEM_PublicKey::algo_name() const {
   return fmt("Hybrid({},{})", public_keys().first->algo_name(), public_keys().second->algo_name());
}

AlgorithmIdentifier Hybrid_TLS_KEM_PublicKey::algorithm_identifier() const {
   throw Botan::Not_Implemented("Hybrid keys don't have an algorithm identifier");
}

std::unique_ptr<Private_Key> Hybrid_TLS_KEM_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Hybrid_TLS_KEM_PrivateKey>(PairOfPrivateKeys{
      public_keys().first->generate_another(rng),
      public_keys().second->generate_another(rng),
   });
}

std::unique_ptr<Botan::PK_Ops::KEM_Encryption> Hybrid_TLS_KEM_PublicKey::create_kem_encryption_op(
   std::string_view params, std::string_view provider) const {
   if(params != "Raw" && !params.empty()) {
      throw Botan::Invalid_Argument("Hybrid KEM encryption does not support KDFs");
   }
   return std::make_unique<Hybrid_TLS_KEM_Encryptor>(public_keys(), provider);
}

std::unique_ptr<Hybrid_TLS_KEM_PrivateKey> Hybrid_TLS_KEM_PrivateKey::generate_from_group(Group_Params group,
                                                                                          RandomNumberGenerator& rng) {
   const auto algo_spec = algorithm_specs_for_group(group);
   return std::make_unique<Hybrid_TLS_KEM_PrivateKey>(PairOfPrivateKeys{
      create_private_key(algo_spec.first.type, rng, algo_spec.first.param),
      create_private_key(algo_spec.second.type, rng, algo_spec.second.param),
   });
}

std::unique_ptr<Botan::PK_Ops::KEM_Decryption> Hybrid_TLS_KEM_PrivateKey::create_kem_decryption_op(
   RandomNumberGenerator& rng, std::string_view params, std::string_view provider) const {
   if(params != "Raw" && !params.empty()) {
      throw Botan::Invalid_Argument("Hybrid KEM decryption does not support KDFs");
   }
   return std::make_unique<Hybrid_TLS_KEM_Decryptor>(private_keys(), rng, provider);
}

}  // namespace Botan::TLS

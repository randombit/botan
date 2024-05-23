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

Hybrid_KEM_PublicKey::Hybrid_KEM_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks) {
   BOTAN_ARG_CHECK(pks.size() >= 2, "List of public keys must include at least two keys");
   BOTAN_ARG_CHECK(std::all_of(pks.begin(), pks.end(), [](const auto& pk) { return pk != nullptr; }),
                   "List of public keys contains a nullptr");
   BOTAN_ARG_CHECK(std::all_of(pks.begin(),
                               pks.end(),
                               [](const auto& pk) {
                                  return pk->supports_operation(PublicKeyOperation::KeyEncapsulation) ||
                                         pk->supports_operation(PublicKeyOperation::KeyAgreement);
                               }),
                   "Some provided public key is not compatible with this hybrid wrapper");

   std::transform(
      pks.begin(), pks.end(), std::back_inserter(m_public_keys), [](auto& key) -> std::unique_ptr<Public_Key> {
         if(key->supports_operation(PublicKeyOperation::KeyAgreement) &&
            !key->supports_operation(PublicKeyOperation::KeyEncapsulation)) {
            return std::make_unique<KEX_to_KEM_Adapter_PublicKey>(std::move(key));
         } else {
            return std::move(key);
         }
      });

   m_key_length =
      reduce(m_public_keys, size_t(0), [](size_t kl, const auto& key) { return std::max(kl, key->key_length()); });
   m_estimated_strength = reduce(
      m_public_keys, size_t(0), [](size_t es, const auto& key) { return std::max(es, key->estimated_strength()); });
}

std::string Hybrid_KEM_PublicKey::algo_name() const {
   std::ostringstream algo_name("Hybrid(");
   for(size_t i = 0; i < m_public_keys.size(); ++i) {
      if(i > 0) {
         algo_name << ",";
      }
      algo_name << m_public_keys[i]->algo_name();
   }
   algo_name << ")";
   return algo_name.str();
}

size_t Hybrid_KEM_PublicKey::estimated_strength() const {
   return m_estimated_strength;
}

size_t Hybrid_KEM_PublicKey::key_length() const {
   return m_key_length;
}

bool Hybrid_KEM_PublicKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return reduce(m_public_keys, true, [&](bool ckr, const auto& key) { return ckr && key->check_key(rng, strong); });
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
   return reduce(m_public_keys, std::vector<uint8_t>(), [](auto pkb, const auto& key) {
      return concat(pkb, key->raw_public_key_bits());
   });
}

std::unique_ptr<Private_Key> Hybrid_KEM_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   std::vector<std::unique_ptr<Private_Key>> new_private_keys;
   std::transform(
      m_public_keys.begin(), m_public_keys.end(), std::back_inserter(new_private_keys), [&](const auto& public_key) {
         return public_key->generate_another(rng);
      });
   return std::make_unique<Hybrid_KEM_PrivateKey>(std::move(new_private_keys));
}

bool Hybrid_KEM_PublicKey::supports_operation(PublicKeyOperation op) const {
   return PublicKeyOperation::KeyEncapsulation == op;
}

namespace {

class Hybrid_KEM_Encryption_Operation final : public PK_Ops::KEM_Encryption_with_KDF {
   public:
      Hybrid_KEM_Encryption_Operation(const Hybrid_KEM_PublicKey& key,
                                      std::string_view kdf,
                                      std::string_view provider) :
            PK_Ops::KEM_Encryption_with_KDF(kdf), m_raw_kem_shared_key_length(0), m_encapsulated_key_length(0) {
         m_kem_encryptors.reserve(key.public_keys().size());
         for(const auto& k : key.public_keys()) {
            const auto& newenc = m_kem_encryptors.emplace_back(*k, "Raw", provider);
            m_raw_kem_shared_key_length += newenc.shared_key_length(0 /* no KDF */);
            m_encapsulated_key_length += newenc.encapsulated_key_length();
         }
      }

      size_t raw_kem_shared_key_length() const override { return m_raw_kem_shared_key_length; }

      size_t encapsulated_key_length() const override { return m_encapsulated_key_length; }

      void raw_kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                           std::span<uint8_t> raw_shared_key,
                           Botan::RandomNumberGenerator& rng) override {
         BOTAN_ASSERT_NOMSG(out_encapsulated_key.size() == encapsulated_key_length());
         BOTAN_ASSERT_NOMSG(raw_shared_key.size() == raw_kem_shared_key_length());

         BufferStuffer encaps_key_stuffer(out_encapsulated_key);
         BufferStuffer shared_key_stuffer(raw_shared_key);

         for(auto& kem_enc : m_kem_encryptors) {
            kem_enc.encrypt(encaps_key_stuffer.next(kem_enc.encapsulated_key_length()),
                            shared_key_stuffer.next(kem_enc.shared_key_length(0 /* no KDF */)),
                            rng);
         }
      }

   private:
      std::vector<PK_KEM_Encryptor> m_kem_encryptors;
      size_t m_raw_kem_shared_key_length;
      size_t m_encapsulated_key_length;
};

}  // namespace

std::unique_ptr<Botan::PK_Ops::KEM_Encryption> Hybrid_KEM_PublicKey::create_kem_encryption_op(
   std::string_view kdf, std::string_view provider) const {
   return std::make_unique<Hybrid_KEM_Encryption_Operation>(*this, kdf, provider);
}

namespace {

auto extract_public_keys(const std::vector<std::unique_ptr<Private_Key>>& private_keys) {
   std::vector<std::unique_ptr<Public_Key>> public_keys;
   public_keys.reserve(private_keys.size());
   for(const auto& private_key : private_keys) {
      BOTAN_ARG_CHECK(private_key != nullptr, "List of private keys contains a nullptr");
      public_keys.push_back(private_key->public_key());
   }
   return public_keys;
}

}  // namespace

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

Hybrid_KEM_PrivateKey::Hybrid_KEM_PrivateKey(std::vector<std::unique_ptr<Private_Key>> sks) :
      Hybrid_KEM_PublicKey(extract_public_keys(sks)) {
   BOTAN_ARG_CHECK(sks.size() >= 2, "List of private keys must include at least two keys");
   BOTAN_ARG_CHECK(std::all_of(sks.begin(),
                               sks.end(),
                               [](const auto& sk) {
                                  return sk->supports_operation(PublicKeyOperation::KeyEncapsulation) ||
                                         sk->supports_operation(PublicKeyOperation::KeyAgreement);
                               }),
                   "Some provided private key is not compatible with this hybrid wrapper");

   std::transform(
      sks.begin(), sks.end(), std::back_inserter(m_private_keys), [](auto& key) -> std::unique_ptr<Private_Key> {
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
}

secure_vector<uint8_t> Hybrid_KEM_PrivateKey::private_key_bits() const {
   throw Not_Implemented("Hybrid private keys cannot be serialized");
}

std::unique_ptr<Public_Key> Hybrid_KEM_PrivateKey::public_key() const {
   return std::make_unique<Hybrid_KEM_PublicKey>(extract_public_keys(m_private_keys));
}

bool Hybrid_KEM_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return reduce(m_public_keys, true, [&](bool ckr, const auto& key) { return ckr && key->check_key(rng, strong); });
}

namespace {

class Hybrid_KEM_Decryption final : public PK_Ops::KEM_Decryption_with_KDF {
   public:
      Hybrid_KEM_Decryption(const Hybrid_KEM_PrivateKey& key,
                            RandomNumberGenerator& rng,
                            const std::string_view kdf,
                            const std::string_view provider) :
            PK_Ops::KEM_Decryption_with_KDF(kdf), m_encapsulated_key_length(0), m_raw_kem_shared_key_length(0) {
         m_decryptors.reserve(key.private_keys().size());
         for(const auto& private_key : key.private_keys()) {
            const auto& newdec = m_decryptors.emplace_back(*private_key, rng, "Raw", provider);
            m_encapsulated_key_length += newdec.encapsulated_key_length();
            m_raw_kem_shared_key_length += newdec.shared_key_length(0 /* no KDF */);
         }
      }

      void raw_kem_decrypt(std::span<uint8_t> out_shared_key, std::span<const uint8_t> encap_key) override {
         BOTAN_ASSERT_NOMSG(out_shared_key.size() == raw_kem_shared_key_length());
         BOTAN_ASSERT_NOMSG(encap_key.size() == encapsulated_key_length());

         BufferSlicer encap_key_slicer(encap_key);
         BufferStuffer shared_secret_stuffer(out_shared_key);

         for(auto& decryptor : m_decryptors) {
            decryptor.decrypt(shared_secret_stuffer.next(decryptor.shared_key_length(0 /* no KDF */)),
                              encap_key_slicer.take(decryptor.encapsulated_key_length()));
         }
      }

      size_t encapsulated_key_length() const override { return m_encapsulated_key_length; }

      size_t raw_kem_shared_key_length() const override { return m_raw_kem_shared_key_length; }

   private:
      std::vector<PK_KEM_Decryptor> m_decryptors;
      size_t m_encapsulated_key_length;
      size_t m_raw_kem_shared_key_length;
};

}  // namespace

std::unique_ptr<Botan::PK_Ops::KEM_Decryption> Hybrid_KEM_PrivateKey::create_kem_decryption_op(
   RandomNumberGenerator& rng, std::string_view kdf, std::string_view provider) const {
   return std::make_unique<Hybrid_KEM_Decryption>(*this, rng, kdf, provider);
}

}  // namespace Botan::TLS

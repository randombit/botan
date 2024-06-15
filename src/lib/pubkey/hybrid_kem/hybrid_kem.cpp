/**
* Abstraction for a combined KEM public and private key.
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/hybrid_kem.h>

#include <botan/pk_algs.h>
#include <botan/internal/fmt.h>
#include <botan/internal/kex_to_kem_adapter.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/stl_util.h>

namespace Botan {

Hybrid_PublicKey::Hybrid_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks) : m_pks(std::move(pks)) {
   BOTAN_ARG_CHECK(m_pks.size() >= 2, "List of public keys must include at least two keys");
   BOTAN_ARG_CHECK(std::all_of(m_pks.begin(), m_pks.end(), [](const auto& pk) { return pk != nullptr; }),
                   "List of public keys contains a nullptr");
   BOTAN_ARG_CHECK(
      std::all_of(m_pks.begin(),
                  m_pks.end(),
                  [](const auto& pk) { return pk->supports_operation(PublicKeyOperation::KeyEncapsulation); }),
      "Some provided public key is not compatible with this hybrid wrapper");
   m_key_length = reduce(m_pks, size_t(0), [](size_t kl, const auto& key) { return std::max(kl, key->key_length()); });
   m_estimated_strength =
      reduce(m_pks, size_t(0), [](size_t es, const auto& key) { return std::max(es, key->estimated_strength()); });
}

bool Hybrid_PublicKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return reduce(public_keys(), true, [&](bool ckr, const auto& key) { return ckr && key->check_key(rng, strong); });
}

std::vector<uint8_t> Hybrid_PublicKey::raw_public_key_bits() const {
   return reduce(public_keys(), std::vector<uint8_t>(), [](auto pkb, const auto& key) {
      return concat(pkb, key->raw_public_key_bits());
   });
}

bool Hybrid_PublicKey::supports_operation(PublicKeyOperation op) const {
   return PublicKeyOperation::KeyEncapsulation == op;
}

std::vector<std::unique_ptr<Private_Key>> Hybrid_PublicKey::generate_other_sks_from_pks(
   RandomNumberGenerator& rng) const {
   std::vector<std::unique_ptr<Private_Key>> new_private_keys;
   std::transform(
      public_keys().begin(), public_keys().end(), std::back_inserter(new_private_keys), [&](const auto& public_key) {
         return public_key->generate_another(rng);
      });
   return new_private_keys;
}

Hybrid_PrivateKey::Hybrid_PrivateKey(std::vector<std::unique_ptr<Private_Key>> private_keys) :
      m_sks(std::move(private_keys)) {
   BOTAN_ARG_CHECK(m_sks.size() >= 2, "List of secret keys must include at least two keys");
   BOTAN_ARG_CHECK(std::all_of(m_sks.begin(), m_sks.end(), [](const auto& sk) { return sk != nullptr; }),
                   "List of secret keys contains a nullptr");
   BOTAN_ARG_CHECK(
      std::all_of(m_sks.begin(),
                  m_sks.end(),
                  [](const auto& sk) { return sk->supports_operation(PublicKeyOperation::KeyEncapsulation); }),
      "Some provided secret key is not compatible with this hybrid wrapper");
}

secure_vector<uint8_t> Hybrid_PrivateKey::private_key_bits() const {
   throw Not_Implemented("Hybrid private keys cannot be serialized");
}

bool Hybrid_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return reduce(private_keys(), true, [&](bool ckr, const auto& key) { return ckr && key->check_key(rng, strong); });
}

std::vector<std::unique_ptr<Public_Key>> Hybrid_PrivateKey::extract_public_keys(
   const std::vector<std::unique_ptr<Private_Key>>& private_keys) {
   std::vector<std::unique_ptr<Public_Key>> public_keys;
   public_keys.reserve(private_keys.size());
   for(const auto& private_key : private_keys) {
      BOTAN_ARG_CHECK(private_key != nullptr, "List of private keys contains a nullptr");
      public_keys.push_back(private_key->public_key());
   }
   return public_keys;
}

}  // namespace Botan

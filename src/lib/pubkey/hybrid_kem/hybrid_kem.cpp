/**
* Abstraction for a combined KEM public and private key.
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*     2026 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/internal/hybrid_kem.h>

#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/kex_to_kem_adapter.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

void maybe_wrap_into_kex_adapter(std::unique_ptr<Public_Key>& pk) {
   if(pk->supports_operation(PublicKeyOperation::KeyAgreement) &&
      !pk->supports_operation(PublicKeyOperation::KeyEncapsulation)) {
      pk = std::make_unique<KEX_to_KEM_Adapter_PublicKey>(std::move(pk));
   }
}

void maybe_wrap_into_kex_adapter(std::unique_ptr<Private_Key>& pk) {
   if(pk->supports_operation(PublicKeyOperation::KeyAgreement) &&
      !pk->supports_operation(PublicKeyOperation::KeyEncapsulation)) {
      pk = std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(std::move(pk));
   }
}

}  // namespace

Hybrid_KEM_PublicKey::Hybrid_KEM_PublicKey(PairOfPublicKeys pks) {
   BOTAN_ARG_CHECK(pks.first != nullptr, "Hybrid_KEM_PublicKey: First public key is a nullptr");
   BOTAN_ARG_CHECK(pks.second != nullptr, "Hybrid_KEM_PublicKey: Second public key is a nullptr");

   maybe_wrap_into_kex_adapter(pks.first);
   maybe_wrap_into_kex_adapter(pks.second);

   BOTAN_ARG_CHECK(pks.first->supports_operation(PublicKeyOperation::KeyEncapsulation),
                   "Hybrid_KEM_PublicKey: First public key is not compatible with this hybrid wrapper");
   BOTAN_ARG_CHECK(pks.second->supports_operation(PublicKeyOperation::KeyEncapsulation),
                   "Hybrid_KEM_PublicKey: Second public key is not compatible with this hybrid wrapper");

   m_pks = std::move(pks);
}

size_t Hybrid_KEM_PublicKey::estimated_strength() const {
   return std::max(m_pks.first->estimated_strength(), m_pks.second->estimated_strength());
}

size_t Hybrid_KEM_PublicKey::key_length() const {
   return std::max(m_pks.first->key_length(), m_pks.second->key_length());
}

bool Hybrid_KEM_PublicKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return m_pks.first->check_key(rng, strong) && m_pks.second->check_key(rng, strong);
}

std::vector<uint8_t> Hybrid_KEM_PublicKey::raw_public_key_bits() const {
   return concat(m_pks.first->raw_public_key_bits(), m_pks.second->raw_public_key_bits());
}

std::vector<uint8_t> Hybrid_KEM_PublicKey::public_key_bits() const {
   return concat(m_pks.first->public_key_bits(), m_pks.second->public_key_bits());
}

bool Hybrid_KEM_PublicKey::supports_operation(PublicKeyOperation op) const {
   return PublicKeyOperation::KeyEncapsulation == op;
}

Hybrid_KEM_PrivateKey::Hybrid_KEM_PrivateKey(PairOfPrivateKeys private_keys) {
   BOTAN_ARG_CHECK(private_keys.first != nullptr, "Hybrid_KEM_PrivateKey: First private key is a nullptr");
   BOTAN_ARG_CHECK(private_keys.second != nullptr, "Hybrid_KEM_PrivateKey: Second private key is a nullptr");

   maybe_wrap_into_kex_adapter(private_keys.first);
   maybe_wrap_into_kex_adapter(private_keys.second);

   BOTAN_ARG_CHECK(private_keys.first->supports_operation(PublicKeyOperation::KeyEncapsulation),
                   "Hybrid_KEM_PrivateKey: First private key is not compatible with this hybrid wrapper");
   BOTAN_ARG_CHECK(private_keys.second->supports_operation(PublicKeyOperation::KeyEncapsulation),
                   "Hybrid_KEM_PrivateKey: Second private key is not compatible with this hybrid wrapper");

   m_sks = std::move(private_keys);
}

secure_vector<uint8_t> Hybrid_KEM_PrivateKey::private_key_bits() const {
   throw Not_Implemented("Hybrid private keys cannot be serialized");
}

bool Hybrid_KEM_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return m_sks.first->check_key(rng, strong) && m_sks.second->check_key(rng, strong);
}

PairOfPublicKeys Hybrid_KEM_PrivateKey::extract_public_keys(const PairOfPrivateKeys& private_keys) {
   BOTAN_ARG_CHECK(private_keys.first != nullptr, "Hybrid_KEM_PrivateKey: First private key is a nullptr");
   BOTAN_ARG_CHECK(private_keys.second != nullptr, "Hybrid_KEM_PrivateKey: Second private key is a nullptr");

   return PairOfPublicKeys{
      private_keys.first->public_key(),
      private_keys.second->public_key(),
   };
}

}  // namespace Botan

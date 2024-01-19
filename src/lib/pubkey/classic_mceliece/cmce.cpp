/*
 * Classic McEliece Key Generation
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/cmce.h>
#include <botan/pk_ops.h>
#include <botan/rng.h>
#include <botan/internal/cmce_decaps.h>
#include <botan/internal/cmce_encaps.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_keys_internal.h>
#include <botan/internal/cmce_matrix.h>
#include <botan/internal/pk_ops_impl.h>

#include <algorithm>

namespace Botan {

Classic_McEliece_PublicKey::Classic_McEliece_PublicKey(const AlgorithmIdentifier& alg_id,
                                                       std::span<const uint8_t> key_bits) :
      Classic_McEliece_PublicKey(key_bits, cmce_param_set_from_oid(alg_id.oid())) {}

Classic_McEliece_PublicKey::Classic_McEliece_PublicKey(std::span<const uint8_t> key_bits,
                                                       Classic_McEliece_Parameter_Set param_set) {
   auto params = Classic_McEliece_Parameters::create(param_set);
   BOTAN_ARG_CHECK(key_bits.size() == params.pk_size_bytes(), "Wrong public key length");
   m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(
      params, Classic_McEliece_Matrix(params, {key_bits.begin(), key_bits.end()}));
}

Classic_McEliece_PublicKey::Classic_McEliece_PublicKey(const Classic_McEliece_PublicKey& other) {
   m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(*other.m_public);
}

Classic_McEliece_PublicKey& Classic_McEliece_PublicKey::operator=(const Classic_McEliece_PublicKey& other) {
   if(this != &other) {
      m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(*other.m_public);
   }
   return *this;
}

AlgorithmIdentifier Classic_McEliece_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

OID Classic_McEliece_PublicKey::object_identifier() const {
   return m_public->params().object_identifier();
}

size_t Classic_McEliece_PublicKey::key_length() const {
   return m_public->matrix().bytes().size();
}

size_t Classic_McEliece_PublicKey::estimated_strength() const {
   return m_public->params().estimated_strength();
}

std::vector<uint8_t> Classic_McEliece_PublicKey::public_key_bits() const {
   return m_public->matrix().bytes();
}

bool Classic_McEliece_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   return true;
}

std::unique_ptr<Private_Key> Classic_McEliece_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Classic_McEliece_PrivateKey>(rng, m_public->params().parameter_set());
}

std::unique_ptr<PK_Ops::KEM_Encryption> Classic_McEliece_PublicKey::create_kem_encryption_op(
   std::string_view params, std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      return std::make_unique<Classic_McEliece_Encryptor>(this->m_public, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

Classic_McEliece_PrivateKey::Classic_McEliece_PrivateKey(RandomNumberGenerator& rng,
                                                         Classic_McEliece_Parameter_Set param_set) {
   auto params = Classic_McEliece_Parameters::create(param_set);
   auto seed = rng.random_vec<CmceInitialSeed>(params.seed_len());
   std::tie(m_private, m_public) = Classic_McEliece_KeyPair_Internal::generate(params, seed).decompose_to_pair();
}

Classic_McEliece_PrivateKey::Classic_McEliece_PrivateKey(std::span<const uint8_t> sk,
                                                         Classic_McEliece_Parameter_Set param_set) {
   auto params = Classic_McEliece_Parameters::create(param_set);
   auto sk_internal = Classic_McEliece_PrivateKeyInternal::from_bytes(params, sk);
   m_private = std::make_shared<Classic_McEliece_PrivateKeyInternal>(std::move(sk_internal));
   // This creates and loads the public key, which is very large. Potentially, we could only load
   // it on demand (since one may use the private key only for decapsulation without needing the public key).
   // TODO: consider building a load-on-demand mechanism for the public key
   m_public = Classic_McEliece_PublicKeyInternal::create_from_private_key(*m_private);
}

Classic_McEliece_PrivateKey::Classic_McEliece_PrivateKey(const AlgorithmIdentifier& alg_id,
                                                         std::span<const uint8_t> key_bits) :
      Classic_McEliece_PrivateKey(key_bits, cmce_param_set_from_oid(alg_id.oid())) {}

std::unique_ptr<Public_Key> Classic_McEliece_PrivateKey::public_key() const {
   return std::make_unique<Classic_McEliece_PublicKey>(*this);
}

secure_vector<uint8_t> Classic_McEliece_PrivateKey::private_key_bits() const {
   return raw_private_key_bits();
}

secure_vector<uint8_t> Classic_McEliece_PrivateKey::raw_private_key_bits() const {
   return m_private->serialize();
}

bool Classic_McEliece_PrivateKey::check_key(RandomNumberGenerator&, bool) const {
   auto prg = m_private->params().prg(m_private->delta());

   const auto s = prg->output<CmceRejectionSeed>(m_private->params().n() / 8);
   const auto ordering_bits =
      prg->output<CmceOrderingBits>((m_private->params().sigma2() * m_private->params().q()) / 8);
   const auto irreducible_bits =
      prg->output<CmceIrreducibleBits>((m_private->params().sigma1() * m_private->params().t()) / 8);

   // Recomputing s as hash of delta
   auto ret =
      CT::Mask<size_t>::expand(CT::is_equal<uint8_t>(s.data(), m_private->s().data(), m_private->params().n() / 8));

   // Checking weight of c
   ret &= CT::Mask<size_t>::is_equal(m_private->c().ct_hamming_weight(), 32);

   if(auto g = m_private->params().poly_ring().compute_minimal_polynomial(irreducible_bits)) {
      for(size_t i = 0; i < g->degree() - 1; ++i) {
         ret &= CT::Mask<size_t>::expand(GF_Mask::is_equal(g->coef_at(i), m_private->g().coef_at(i)).elem_mask());
      }
   } else {
      ret = CT::Mask<size_t>::cleared();
   }

   // Check alpha control bits
   if(auto field_ord_from_seed =
         Classic_McEliece_Field_Ordering::create_field_ordering(m_private->params(), ordering_bits)) {
      field_ord_from_seed->permute_with_pivots(m_private->params(), m_private->c());
      ret &= CT::Mask<size_t>::expand(field_ord_from_seed->ct_is_equal(m_private->field_ordering()));
   } else {
      ret = CT::Mask<size_t>::cleared();
   }

   return ret.as_bool();
}

std::unique_ptr<PK_Ops::KEM_Decryption> Classic_McEliece_PrivateKey::create_kem_decryption_op(
   RandomNumberGenerator& rng, std::string_view params, std::string_view provider) const {
   BOTAN_UNUSED(rng);
   if(provider.empty() || provider == "base") {
      return std::make_unique<Classic_McEliece_Decryptor>(this->m_private, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan

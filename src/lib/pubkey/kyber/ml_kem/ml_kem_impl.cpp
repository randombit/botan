/*
 * Module-Lattice Key Encapsulation Mechanism (ML-KEM), Initial Public Draft
 *
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/ml_kem_impl.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/kyber_algos.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_types.h>

namespace Botan {

/**
 * NIST FIPS 203, Algorithm 17 (ML-KEM.Encaps_internal), and 20 (ML-KEM.Encaps)
 *
 * Generation of the random value is inlined with its usage. The public matrix
 * A^T as well as H(pk) are precomputed and readily available.
 */
void ML_KEM_Encryptor::encapsulate(StrongSpan<KyberCompressedCiphertext> out_encapsulated_key,
                                   StrongSpan<KyberSharedSecret> out_shared_key,
                                   RandomNumberGenerator& rng) {
   const auto& sym = m_public_key->mode().symmetric_primitives();

   const auto m = rng.random_vec<KyberMessage>(KyberConstants::SEED_BYTES);
   auto scope = CT::scoped_poison(m);

   const auto [K, r] = sym.G(m, m_public_key->H_public_key_bits_raw());
   m_public_key->indcpa_encrypt(out_encapsulated_key, m, r, precomputed_matrix_At());

   // TODO: avoid this copy by letting sym.G() directly write to the span.
   copy_mem(out_shared_key, K);
   CT::unpoison_all(out_shared_key, out_encapsulated_key);
}

/**
 * NIST FIPS 203, Algorithm 18 (ML-KEM.Decaps_internal) and 21 (ML-KEM.Decaps)
 *
 * The public and private keys are readily available as member variables and
 * don't need to be decoded. The checks stated in FIPS 203, Section 7.3 are
 * performed before decoding the keys and the ciphertext.
 */
void ML_KEM_Decryptor::decapsulate(StrongSpan<KyberSharedSecret> out_shared_key,
                                   StrongSpan<const KyberCompressedCiphertext> c) {
   auto scope = CT::scoped_poison(*m_private_key);

   const auto& sym = m_public_key->mode().symmetric_primitives();

   const auto& h = m_public_key->H_public_key_bits_raw();
   const auto& z = m_private_key->z();

   const auto m_prime = m_private_key->indcpa_decrypt(c);
   const auto [K_prime, r_prime] = sym.G(m_prime, h);

   const auto K_bar = sym.J(z, c);
   const auto c_prime = m_public_key->indcpa_encrypt(m_prime, r_prime, precomputed_matrix_At());

   BOTAN_ASSERT_NOMSG(c.size() == c_prime.size());
   BOTAN_ASSERT_NOMSG(K_prime.size() == K_bar.size() && out_shared_key.size() == K_bar.size());
   const auto reencrypt_success = CT::is_equal(c.data(), c_prime.data(), c.size());
   CT::conditional_copy_mem(reencrypt_success, out_shared_key.data(), K_prime.data(), K_bar.data(), K_prime.size());

   CT::unpoison(out_shared_key);
}

KyberInternalKeypair ML_KEM_Expanding_Keypair_Codec::decode_keypair(std::span<const uint8_t> private_key,
                                                                    KyberConstants mode) const {
   BufferSlicer s(private_key);
   auto seed = KyberPrivateKeySeed{
      s.copy<KyberSeedRandomness>(KyberConstants::SEED_BYTES),
      s.copy<KyberImplicitRejectionValue>(KyberConstants::SEED_BYTES),
   };
   BOTAN_ASSERT_NOMSG(s.empty());
   return Kyber_Algos::expand_keypair(std::move(seed), std::move(mode));
}

secure_vector<uint8_t> ML_KEM_Expanding_Keypair_Codec::encode_keypair(KyberInternalKeypair keypair) const {
   BOTAN_ASSERT_NONNULL(keypair.second);
   const auto& seed = keypair.second->seed();
   BOTAN_ARG_CHECK(seed.d.has_value(), "Cannot encode keypair without the full private seed");
   return concat<secure_vector<uint8_t>>(seed.d.value(), seed.z);
};

}  // namespace Botan

/*
 * Crystals Kyber key encapsulation mechanism and key codec
 *
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/kyber_round3_impl.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/kyber_types.h>

namespace Botan {

/**
 * Crystals Kyber (Version 3.01), Algorithm 8 (Kyber.CCAKEM.Enc())
 */
void Kyber_KEM_Encryptor::encapsulate(StrongSpan<KyberCompressedCiphertext> out_encapsulated_key,
                                      StrongSpan<KyberSharedSecret> out_shared_key,
                                      RandomNumberGenerator& rng) {
   const auto& sym = m_public_key->mode().symmetric_primitives();

   const auto seed_m = rng.random_vec<KyberMessage>(KyberConstants::SEED_BYTES);
   CT::poison(seed_m);

   const auto m = sym.H(seed_m);
   const auto [K_bar, r] = sym.G(m, m_public_key->H_public_key_bits_raw());
   m_public_key->indcpa_encrypt(out_encapsulated_key, m, r, precomputed_matrix_At());

   sym.KDF(out_shared_key, K_bar, sym.H(out_encapsulated_key));
   CT::unpoison_all(out_shared_key, out_encapsulated_key);
}

/**
 * Crystals Kyber (Version 3.01), Algorithm 9 (Kyber.CCAKEM.Dec())
 */
void Kyber_KEM_Decryptor::decapsulate(StrongSpan<KyberSharedSecret> out_shared_key,
                                      StrongSpan<const KyberCompressedCiphertext> encapsulated_key) {
   auto scope = CT::scoped_poison(*m_private_key);

   const auto& sym = m_public_key->mode().symmetric_primitives();

   const auto& h = m_public_key->H_public_key_bits_raw();
   const auto& z = m_private_key->z();

   const auto m_prime = m_private_key->indcpa_decrypt(encapsulated_key);
   const auto [K_bar_prime, r_prime] = sym.G(m_prime, h);

   const auto c_prime = m_public_key->indcpa_encrypt(m_prime, r_prime, precomputed_matrix_At());

   KyberSharedSecret K(KyberConstants::SEED_BYTES);
   BOTAN_ASSERT_NOMSG(encapsulated_key.size() == c_prime.size());
   BOTAN_ASSERT_NOMSG(K_bar_prime.size() == K.size());
   const auto reencrypt_success = CT::is_equal(encapsulated_key.data(), c_prime.data(), encapsulated_key.size());
   CT::conditional_copy_mem(reencrypt_success, K.data(), K_bar_prime.data(), z.data(), K_bar_prime.size());

   sym.KDF(out_shared_key, K, sym.H(encapsulated_key));
   CT::unpoison(out_shared_key);
}

/**
 * Key decoding as specified in Crystals Kyber (Version 3.01),
 * Algorithms 4 (CPAPKE.KeyGen()), and 7 (CCAKEM.KeyGen())
 *
 * Public Key: pk  := (encode(t) || rho)
 * Secret Key: sk' := encode(s)
 *
 * Expanded Secret Key: sk  := (sk' || pk || H(pk) || z)
 */
KyberInternalKeypair Kyber_Expanded_Keypair_Codec::decode_keypair(std::span<const uint8_t> sk,
                                                                  KyberConstants mode) const {
   auto scope = CT::scoped_poison(sk);
   BufferSlicer s(sk);

   auto skpv = Kyber_Algos::decode_polynomial_vector(s.take(mode.polynomial_vector_bytes()), mode);
   auto pub_key = s.copy<KyberSerializedPublicKey>(mode.public_key_bytes());
   auto puk_key_hash = s.take<KyberHashedPublicKey>(KyberConstants::PUBLIC_KEY_HASH_BYTES);
   auto z = s.copy<KyberImplicitRejectionValue>(KyberConstants::SEED_BYTES);

   BOTAN_ASSERT_NOMSG(s.empty());

   CT::unpoison_all(pub_key, puk_key_hash, skpv, z);

   KyberInternalKeypair keypair{
      std::make_shared<Kyber_PublicKeyInternal>(mode, std::move(pub_key)),
      std::make_shared<Kyber_PrivateKeyInternal>(
         std::move(mode),
         std::move(skpv),
         KyberPrivateKeySeed{std::nullopt,  // Reading from an expanded and encoded
                                            // private key cannot reconstruct the
                                            // original seed from key generation.
                             std::move(z)}),
   };

   BOTAN_ASSERT(keypair.first && keypair.second, "reading private key encoding");
   BOTAN_ARG_CHECK(keypair.first->H_public_key_bits_raw().size() == puk_key_hash.size() &&
                      std::equal(keypair.first->H_public_key_bits_raw().begin(),
                                 keypair.first->H_public_key_bits_raw().end(),
                                 puk_key_hash.begin()),
                   "public key's hash does not match the stored hash");

   return keypair;
}

secure_vector<uint8_t> Kyber_Expanded_Keypair_Codec::encode_keypair(KyberInternalKeypair keypair) const {
   BOTAN_ASSERT_NONNULL(keypair.first);
   BOTAN_ASSERT_NONNULL(keypair.second);
   const auto& mode = keypair.first->mode();
   auto scope = CT::scoped_poison(*keypair.second);
   auto result = concat(Kyber_Algos::encode_polynomial_vector(keypair.second->s().reduce(), mode),
                        keypair.first->public_key_bits_raw(),
                        keypair.first->H_public_key_bits_raw(),
                        keypair.second->z());
   CT::unpoison(result);
   return result;
}

}  // namespace Botan

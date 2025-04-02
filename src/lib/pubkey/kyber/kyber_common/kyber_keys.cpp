/*
 * Crystals Kyber Internal Key Types
 *
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Fabian Albert, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/kyber_keys.h>

#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

KyberSerializedPublicKey validate_public_key_length(KyberSerializedPublicKey public_key, size_t expected_length) {
   if(public_key.size() != expected_length) {
      throw Invalid_Argument("Public key does not have the correct byte count");
   }
   return public_key;
}

}  // namespace

/**
 * Key decoding as specified in Crystals Kyber (Version 3.01),
 * Algorithms 4 (CPAPKE.KeyGen()), and 7 (CCAKEM.KeyGen())
 *
 * Public Key: pk  := (encode(t) || rho)
 * Secret Key: sk' := encode(s)
 *
 * Expanded Secret Key: sk  := (sk' || pk || H(pk) || z)
 */
KyberInternalKeypair Expanded_Keypair_Codec::decode_keypair(std::span<const uint8_t> sk, KyberConstants mode) const {
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

secure_vector<uint8_t> Expanded_Keypair_Codec::encode_keypair(KyberInternalKeypair keypair) const {
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

KyberInternalKeypair Seed_Expanding_Keypair_Codec::decode_keypair(std::span<const uint8_t> private_key,
                                                                  KyberConstants mode) const {
   BufferSlicer s(private_key);
   auto seed = KyberPrivateKeySeed{
      s.copy<KyberSeedRandomness>(KyberConstants::SEED_BYTES),
      s.copy<KyberImplicitRejectionValue>(KyberConstants::SEED_BYTES),
   };
   BOTAN_ASSERT_NOMSG(s.empty());
   return Kyber_Algos::expand_keypair(std::move(seed), std::move(mode));
}

secure_vector<uint8_t> Seed_Expanding_Keypair_Codec::encode_keypair(KyberInternalKeypair keypair) const {
   BOTAN_ASSERT_NONNULL(keypair.second);
   const auto& seed = keypair.second->seed();
   BOTAN_ARG_CHECK(seed.d.has_value(), "Cannot encode keypair without the full private seed");
   return concat<secure_vector<uint8_t>>(seed.d.value(), seed.z);
};

Kyber_PublicKeyInternal::Kyber_PublicKeyInternal(KyberConstants mode, KyberSerializedPublicKey public_key) :
      m_mode(std::move(mode)),
      m_public_key_bits_raw(validate_public_key_length(std::move(public_key), m_mode.public_key_bytes())),
      m_H_public_key_bits_raw(m_mode.symmetric_primitives().H(m_public_key_bits_raw)),
      m_t(Kyber_Algos::decode_polynomial_vector(
         std::span{m_public_key_bits_raw}.first(m_mode.polynomial_vector_bytes()), m_mode)),
      m_rho(std::span{m_public_key_bits_raw}.last(Botan::KyberConstants::SEED_BYTES)) {}

Kyber_PublicKeyInternal::Kyber_PublicKeyInternal(KyberConstants mode, KyberPolyVecNTT t, KyberSeedRho rho) :
      m_mode(std::move(mode)),
      m_public_key_bits_raw(concat(Kyber_Algos::encode_polynomial_vector<std::vector<uint8_t>>(t, m_mode), rho)),
      m_H_public_key_bits_raw(m_mode.symmetric_primitives().H(m_public_key_bits_raw)),
      m_t(std::move(t)),
      m_rho(std::move(rho)) {}

/**
 * NIST FIPS 203, Algorithm 14 (K-PKE.Encrypt)
 *
 * In contrast to FIPS 203, the matrix @p At is not sampled for every invocation,
 * instead it is precomputed and passed in as a parameter. Similarly, the t^T is
 * already decoded and available as a member variable. This allows to reuse these
 * structures for multiple encryptions.
 *
 * The sampling loops spelled out in FIPS 203 are hidden in the sample_* functions.
 */
void Kyber_PublicKeyInternal::indcpa_encrypt(StrongSpan<KyberCompressedCiphertext> out_ct,
                                             StrongSpan<const KyberMessage> m,
                                             StrongSpan<const KyberEncryptionRandomness> r,
                                             const KyberPolyMat& At) const {
   // The nonce N is handled internally by the PolynomialSampler
   Kyber_Algos::PolynomialSampler ps(r, m_mode);
   const auto y = ntt(ps.sample_polynomial_vector_cbd_eta1());
   const auto e1 = ps.sample_polynomial_vector_cbd_eta2();
   const auto e2 = ps.sample_polynomial_cbd_eta2();

   auto u = inverse_ntt(At * y);
   u += e1;
   u.reduce();

   const auto mu = Kyber_Algos::polynomial_from_message(m);
   auto v = inverse_ntt(m_t * y);
   v += e2;
   v += mu;
   v.reduce();

   Kyber_Algos::compress_ciphertext(out_ct, u, v, m_mode);
}

/**
 * NIST FIPS 203, Algorithm 15 (K-PKE.Decrypt)
 *
 * s^T is already decoded and available as a member variable. This allows to reuse
 * the structure for multiple decryptions.
 */
KyberMessage Kyber_PrivateKeyInternal::indcpa_decrypt(StrongSpan<const KyberCompressedCiphertext> ct) const {
   auto [u, v] = Kyber_Algos::decompress_ciphertext(ct, m_mode);
   v -= inverse_ntt(m_s * ntt(std::move(u)));
   v.reduce();
   return Kyber_Algos::polynomial_to_message(v);
}

}  // namespace Botan

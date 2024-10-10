/*
 * Crystals Kyber Internal Algorithms
 * Based on the public domain reference implementation by the
 * designers (https://github.com/pq-crystals/kyber)
 *
 * Further changes
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_ALGOS_H_
#define BOTAN_KYBER_ALGOS_H_

#include <botan/xof.h>
#include <botan/internal/fmt.h>
#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/kyber_types.h>
#include <botan/internal/loadstor.h>

namespace Botan::Kyber_Algos {

void encode_polynomial_vector(std::span<uint8_t> out, const KyberPolyVecNTT& p);

KyberPolyVecNTT decode_polynomial_vector(std::span<const uint8_t> a, const KyberConstants& mode);

KyberPoly polynomial_from_message(StrongSpan<const KyberMessage> msg);

KyberMessage polynomial_to_message(const KyberPoly& p);

KyberInternalKeypair expand_keypair(KyberPrivateKeySeed seed, KyberConstants mode);

void compress_ciphertext(StrongSpan<KyberCompressedCiphertext> out,
                         const KyberPolyVec& u,
                         const KyberPoly& v,
                         const KyberConstants& m_mode);

std::pair<KyberPolyVec, KyberPoly> decompress_ciphertext(StrongSpan<const KyberCompressedCiphertext> ct,
                                                         const KyberConstants& mode);

KyberPolyMat sample_matrix(StrongSpan<const KyberSeedRho> seed, bool transposed, const KyberConstants& mode);

void sample_polynomial_from_cbd(KyberPoly& poly,
                                KyberConstants::KyberEta eta,
                                const KyberSamplingRandomness& randomness);

template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
T encode_polynomial_vector(const KyberPolyVecNTT& vec, const KyberConstants& mode) {
   T r(mode.polynomial_vector_bytes());
   encode_polynomial_vector(r, vec);
   return r;
}

/**
 * Allows sampling multiple polynomials from a single seed via a XOF.
 *
 * Used in Algorithms 13 (K-PKE.KeyGen) and 14 (K-PKE.Encrypt), and takes care
 * of the continuous nonce value internally.
 */
template <typename SeedT>
   requires std::same_as<KyberSeedSigma, SeedT> || std::same_as<KyberEncryptionRandomness, SeedT>
class PolynomialSampler {
   public:
      PolynomialSampler(StrongSpan<const SeedT> seed, const KyberConstants& mode) :
            m_seed(seed), m_mode(mode), m_nonce(0) {}

      KyberPolyVec sample_polynomial_vector_cbd_eta1() {
         KyberPolyVec vec(m_mode.k());
         for(auto& poly : vec) {
            sample_poly_cbd(poly, m_mode.eta1());
         }
         return vec;
      }

      KyberPoly sample_polynomial_cbd_eta2()
         requires std::same_as<KyberEncryptionRandomness, SeedT>
      {
         KyberPoly poly;
         sample_poly_cbd(poly, m_mode.eta2());
         return poly;
      }

      KyberPolyVec sample_polynomial_vector_cbd_eta2()
         requires std::same_as<KyberEncryptionRandomness, SeedT>
      {
         KyberPolyVec vec(m_mode.k());
         for(auto& poly : vec) {
            sample_poly_cbd(poly, m_mode.eta2());
         }
         return vec;
      }

   private:
      KyberSamplingRandomness prf(size_t bytes) { return m_mode.symmetric_primitives().PRF(m_seed, m_nonce++, bytes); }

      void sample_poly_cbd(KyberPoly& poly, KyberConstants::KyberEta eta) {
         const auto randomness = [&] {
            switch(eta) {
               case KyberConstants::KyberEta::_2:
                  return prf(2 * poly.size() / 4);
               case KyberConstants::KyberEta::_3:
                  return prf(3 * poly.size() / 4);
            }

            BOTAN_ASSERT_UNREACHABLE();
         }();

         sample_polynomial_from_cbd(poly, eta, randomness);
      }

   private:
      StrongSpan<const SeedT> m_seed;
      const KyberConstants& m_mode;
      uint8_t m_nonce;
};

template <typename T>
PolynomialSampler(T, const KyberConstants&) -> PolynomialSampler<T>;

}  // namespace Botan::Kyber_Algos

#endif

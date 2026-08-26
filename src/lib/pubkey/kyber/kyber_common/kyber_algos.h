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

#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/kyber_types.h>

#include <array>

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
                                StrongSpan<const KyberSamplingRandomness> randomness);

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
         sample_poly_vec_cbd(vec, m_mode.eta1());
         return vec;
      }

      /// Samples two polynomial vectors in a single PRF batch
      std::pair<KyberPolyVec, KyberPolyVec> sample_polynomial_vector_pair_cbd_eta1() {
         auto result = std::make_pair(KyberPolyVec(m_mode.k()), KyberPolyVec(m_mode.k()));
         std::vector<KyberPoly*> polys;
         collect_polys(polys, result.first);
         collect_polys(polys, result.second);
         sample_polys_cbd(polys, m_mode.eta1());
         return result;
      }

      /// Samples a polynomial vector and a single polynomial in one PRF batch
      std::pair<KyberPolyVec, KyberPoly> sample_polynomial_vector_and_poly_cbd_eta2()
         requires std::same_as<KyberEncryptionRandomness, SeedT>
      {
         std::pair<KyberPolyVec, KyberPoly> result{KyberPolyVec(m_mode.k()), KyberPoly()};
         std::vector<KyberPoly*> polys;
         collect_polys(polys, result.first);
         polys.push_back(&result.second);
         sample_polys_cbd(polys, m_mode.eta2());
         return result;
      }

   private:
      static size_t cbd_randomness_bytes(const KyberPoly& poly, KyberConstants::KyberEta eta) {
         switch(eta) {
            case KyberConstants::KyberEta::_2:
               return 2 * poly.size() / 4;
            case KyberConstants::KyberEta::_3:
               return 3 * poly.size() / 4;
         }

         BOTAN_ASSERT_UNREACHABLE();
      }

      static void collect_polys(std::vector<KyberPoly*>& polys, KyberPolyVec& vec) {
         for(auto& poly : vec) {
            polys.push_back(&poly);
         }
      }

      void sample_poly_vec_cbd(KyberPolyVec& vec, KyberConstants::KyberEta eta) {
         std::vector<KyberPoly*> polys;
         collect_polys(polys, vec);
         sample_polys_cbd(polys, eta);
      }

      /// Samples all @p polys with consecutive nonces, allowing the PRF
      /// outputs to be produced in one batch
      void sample_polys_cbd(std::span<KyberPoly* const> polys, KyberConstants::KyberEta eta) {
         BOTAN_ASSERT_NOMSG(!polys.empty());
         const size_t poly_bytes = cbd_randomness_bytes(*polys[0], eta);

         KyberSamplingRandomness randomness(polys.size() * poly_bytes);
         std::vector<std::span<uint8_t>> outputs(polys.size());
         for(size_t i = 0; i < polys.size(); ++i) {
            outputs[i] = std::span(randomness.get()).subspan(i * poly_bytes, poly_bytes);
         }

         const auto& sym = m_mode.symmetric_primitives();
         sym.PRF_batch(outputs, m_seed.get(), m_nonce);
         m_nonce += static_cast<uint8_t>(polys.size());

         for(size_t i = 0; i < polys.size(); ++i) {
            sample_polynomial_from_cbd(*polys[i], eta, StrongSpan<const KyberSamplingRandomness>(outputs[i]));
         }
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

/*
 * Crystals Dilithium Polynomial Adapter
 *
 * (C) 2022-2023 Jack Lloyd
 * (C) 2022      Manuel Glaser - Rohde & Schwarz Cybersecurity
 * (C) 2022-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_DILITHIUM_POLYNOMIAL_H_
#define BOTAN_DILITHIUM_POLYNOMIAL_H_

#include <botan/mem_ops.h>
#include <botan/internal/dilithium_constants.h>
#include <botan/internal/pqcrystals.h>
#include <botan/internal/pqcrystals_helpers.h>

namespace Botan {

class DilithiumPolyTraits final : public CRYSTALS::Trait_Base<DilithiumConstants, DilithiumPolyTraits> {
   private:
      friend class CRYSTALS::Trait_Base<DilithiumConstants, DilithiumPolyTraits>;

      static constexpr T montgomery_reduce_coefficient(T2 a) {
         const T2 t = static_cast<T>(static_cast<T2>(static_cast<T>(a)) * Q_inverse);
         return (a - static_cast<T2>(t) * Q) >> (sizeof(T) * 8);
      }

      static constexpr T barrett_reduce_coefficient(T a) {
         // 2**22 is roughly Q/2 and 2**23 is roughly Q
         const T t = (a + (1 << 22)) >> 23;
         a = a - t * Q;
         return a;
      }

   public:
      /**
       * NIST FIPS 204, Algorithm 41 (NTT)
       *
       * Note: ntt(), inverse_ntt() and operator* have side effects on the
       *       montgomery factor of the involved coefficients!
       *       It is assumed that EXACTLY ONE vector or matrix multiplication
       *       is performed between transforming in and out of NTT domain.
       *
       * Produces the result of the NTT transformation without any montgomery
       * factors in the coefficients.
       */
      static constexpr void ntt(std::span<T, N> coeffs) {
         size_t j;
         size_t k = 0;

         for(size_t len = N / 2; len > 0; len >>= 1) {
            for(size_t start = 0; start < N; start = j + len) {
               const T zeta = zetas[++k];
               for(j = start; j < start + len; ++j) {
                  // Zetas contain the montgomery parameter 2^32 mod q
                  T t = fqmul(zeta, coeffs[j + len]);
                  coeffs[j + len] = coeffs[j] - t;
                  coeffs[j] = coeffs[j] + t;
               }
            }
         }
      }

      /**
       * NIST FIPS 204, Algorithm 42 (NTT^-1).
       *
       * The output is effectively multiplied by the montgomery parameter 2^32
       * mod q so that the input factors 2^(-32) mod q are eliminated. Note
       * that factors 2^(-32) mod q are introduced by multiplication and
       * reduction of values not in montgomery domain.
       *
       * Produces the result of the inverse NTT transformation with a montgomery
       * factor of (2^32 mod q) added (!). See above.
       */
      static constexpr void inverse_ntt(std::span<T, N> coeffs) {
         size_t j;
         size_t k = N;
         for(size_t len = 1; len < N; len <<= 1) {
            for(size_t start = 0; start < N; start = j + len) {
               const T zeta = -zetas[--k];
               for(j = start; j < start + len; ++j) {
                  T t = coeffs[j];
                  coeffs[j] = t + coeffs[j + len];
                  coeffs[j + len] = t - coeffs[j + len];
                  // Zetas contain the montgomery parameter 2^32 mod q
                  coeffs[j + len] = fqmul(zeta, coeffs[j + len]);
               }
            }
         }

         for(auto& coeff : coeffs) {
            coeff = fqmul(coeff, F_WITH_MONTY_SQUARED);
         }
      }

      /**
       * Multiplication of two polynomials @p lhs and @p rhs in NTT domain.
       *
       * Produces the result of the multiplication in NTT domain, with a factor
       * of (2^-32 mod q) in each element due to montgomery reduction.
       */
      static constexpr void poly_pointwise_montgomery(std::span<T, N> result,
                                                      std::span<const T, N> lhs,
                                                      std::span<const T, N> rhs) {
         for(size_t i = 0; i < N; ++i) {
            result[i] = fqmul(lhs[i], rhs[i]);
         }
      }
};

}  // namespace Botan

#endif

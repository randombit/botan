/*
 * Crystals Kyber Polynomial Adapter
 *
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_POLYNOMIAL_H_
#define BOTAN_KYBER_POLYNOMIAL_H_

#include <botan/kyber.h>
#include <botan/mem_ops.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/pqcrystals.h>
#include <botan/internal/pqcrystals_helpers.h>

namespace Botan {

class Kyber_Symmetric_Primitives;

class KyberPolyTraits final : public CRYSTALS::Trait_Base<KyberConstants, KyberPolyTraits> {
   private:
      friend class CRYSTALS::Trait_Base<KyberConstants, KyberPolyTraits>;

      constexpr static T montgomery_reduce_coefficient(T2 a) {
         const T u = static_cast<T>(a) * Q_inverse;
         auto t = static_cast<T2>(u) * Q;
         t = a - t;
         t >>= sizeof(T) * 8;
         return static_cast<T>(t);
      }

      constexpr static T barrett_reduce_coefficient(T a) {
         constexpr T2 v = ((1U << 26) + Q / 2) / Q;
         const T t = (v * a >> 26) * Q;
         return a - t;
      }

   public:
      /**
       * NIST FIPS 203, Algorithm 9 (NTT)
       *
       * Produces the result of the NTT transformation without any montgomery
       * factors in the coefficients. Zetas are pre-computed and stored in the
       * zetas array. The zeta values contain the montgomery factor 2^16 mod q.
       */
      constexpr static void ntt(std::span<T, N> p) {
         for(size_t len = N / 2, i = 0; len >= 2; len /= 2) {
            for(size_t start = 0, j = 0; start < N; start = j + len) {
               const auto zeta = zetas[++i];
               for(j = start; j < start + len; ++j) {
                  const auto t = fqmul(zeta, p[j + len]);
                  p[j + len] = p[j] - t;
                  p[j] = p[j] + t;
               }
            }
         }

         barrett_reduce(p);
      }

      /**
       * NIST FIPS 203, Algorithm 10 (NTT^-1)
       *
       * The output is effectively multiplied by the montgomery parameter 2^16
       * mod q so that the input factors 2^(-16) mod q are eliminated. Note
       * that factors 2^(-16) mod q are introduced by multiplication and
       * reduction of values not in montgomery domain.
       *
       * Produces the result of the inverse NTT transformation with a montgomery
       * factor of (2^16 mod q) added (!). See above.
       */
      static constexpr void inverse_ntt(std::span<T, N> p) {
         for(size_t len = 2, i = 127; len <= N / 2; len *= 2) {
            for(size_t start = 0, j = 0; start < N; start = j + len) {
               const auto zeta = zetas[i--];
               for(j = start; j < start + len; ++j) {
                  const auto t = p[j];
                  p[j] = barrett_reduce_coefficient(t + p[j + len]);
                  p[j + len] = fqmul(zeta, p[j + len] - t);
               }
            }
         }

         for(auto& c : p) {
            c = fqmul(c, F_WITH_MONTY_SQUARED);
         }
      }

      /**
       * NIST FIPS 203, Algorithms 11 (MultiplyNTTs) and 12 (BaseCaseMultiply)
       *
       * The result contains factors of 2^(-16) mod q (i.e. the inverse montgomery factor).
       * This factor is eliminated by the inverse NTT transformation, see above.
       */
      static constexpr void poly_pointwise_montgomery(std::span<T, N> result,
                                                      std::span<const T, N> lhs,
                                                      std::span<const T, N> rhs) {
         /**
          * NIST FIPS 203, Algorithm 12 (BaseCaseMultiply)
          */
         auto basemul = [](const auto a, const auto b, const T zeta) -> std::tuple<T, T> {
            return {static_cast<T>(fqmul(a[0], b[0]) + fqmul(fqmul(a[1], b[1]), zeta)),
                    static_cast<T>(fqmul(a[0], b[1]) + fqmul(a[1], b[0]))};
         };

         auto Tq_elem_count = [](auto p) { return p.size() / 2; };

         auto Tq_elem = [](auto p, size_t i) {
            if constexpr(std::is_const_v<typename decltype(p)::element_type>) {
               return std::array<T, 2>{p[2 * i], p[2 * i + 1]};
            } else {
               return std::tuple<T&, T&>{p[2 * i], p[2 * i + 1]};
            }
         };

         for(size_t i = 0; i < Tq_elem_count(result) / 2; ++i) {
            const auto zeta = zetas[64 + i];
            Tq_elem(result, 2 * i) = basemul(Tq_elem(lhs, 2 * i), Tq_elem(rhs, 2 * i), zeta);
            Tq_elem(result, 2 * i + 1) = basemul(Tq_elem(lhs, 2 * i + 1), Tq_elem(rhs, 2 * i + 1), -zeta);
         }
      }
};

}  // namespace Botan

#endif

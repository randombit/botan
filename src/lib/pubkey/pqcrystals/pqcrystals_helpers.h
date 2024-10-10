/*
 * PQ CRYSTALS Common Helpers
 *
 * Further changes
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Fabian Albert, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_PQ_CRYSTALS_HELPERS_H_
#define BOTAN_PQ_CRYSTALS_HELPERS_H_

#include <concepts>
#include <cstdint>
#include <span>
#include <tuple>

#include <botan/exceptn.h>
#include <botan/internal/bit_ops.h>

namespace Botan {

// clang-format off

template <std::unsigned_integral T>
   requires(sizeof(T) <= 4)
using next_longer_uint_t =
   std::conditional_t<sizeof(T) == 1, uint16_t,
   std::conditional_t<sizeof(T) == 2, uint32_t,
   std::conditional_t<sizeof(T) == 4, uint64_t, void>>>;

template <std::signed_integral T>
   requires(sizeof(T) <= 4)
using next_longer_int_t =
   std::conditional_t<sizeof(T) == 1, int16_t,
   std::conditional_t<sizeof(T) == 2, int32_t,
   std::conditional_t<sizeof(T) == 4, int64_t, void>>>;

// clang-format on

template <std::integral T>
   requires(size_t(sizeof(T)) <= 4)
consteval T montgomery_R(T q) {
   using T_unsigned = std::make_unsigned_t<T>;
   using T2 = next_longer_uint_t<T_unsigned>;
   return (T2(1) << (sizeof(T) * 8)) % q;
}

template <std::integral T>
   requires(size_t(sizeof(T)) <= 4)
consteval T montgomery_R2(T q) {
   using T2 = next_longer_int_t<T>;
   return (static_cast<T2>(montgomery_R(q)) * static_cast<T2>(montgomery_R(q))) % q;
}

template <std::integral T>
struct eea_result {
      T gcd;
      T u;
      T v;
};

/**
 * Run the extended Euclidean algorithm to find the greatest common divisor of a
 * and b and the Bézout coefficients, u and v.
 */
template <std::integral T>
consteval eea_result<T> extended_euclidean_algorithm(T a, T b) {
   if(a > b) {
      std::swap(a, b);
   }

   T u1 = 0, v1 = 1, u2 = 1, v2 = 0;

   if(a != b) {
      while(a != 0) {
         const T q = b / a;
         std::tie(a, b) = std::make_tuple(static_cast<T>(b - q * a), a);
         std::tie(u1, v1, u2, v2) = std::make_tuple(u2, v2, static_cast<T>(u1 - q * u2), static_cast<T>(v1 - q * v2));
      }
   }

   return {.gcd = b, .u = u1, .v = v1};
}

/**
 * Calculate the modular multiplacative inverse of q modulo m.
 * By default, this assumes m to be 2^bitlength of T for application in a
 * Montgomery reduction.
 */
template <std::integral T, std::integral T2 = next_longer_int_t<T>>
   requires(sizeof(T) <= 4)
consteval T modular_inverse(T q, T2 m = T2(1) << sizeof(T) * 8) {
   return static_cast<T>(extended_euclidean_algorithm<T2>(q, m).u);
}

constexpr auto bitlen(size_t x) {
   return ceil_log2(x + 1);
};

/**
 * Precompute the zeta-values for the NTT. Note that the pre-computed values
 * contain the Montgomery factor for either Kyber or Dilithium.
 */
template <size_t degree, std::integral T>
consteval static auto precompute_zetas(T q, T monty, T root_of_unity) {
   using T2 = next_longer_int_t<T>;

   std::array<T, degree> result = {0};

   auto bitreverse = [](size_t k) -> size_t {
      size_t r = 0;
      const auto l = ceil_log2(degree);
      for(size_t i = 0; i < l; ++i) {
         r |= ((k >> i) & 1) << (l - 1 - i);
      }
      return r;
   };

   auto pow = [q](T base, size_t exp) -> T2 {
      T2 res = 1;
      for(size_t i = 0; i < exp; ++i) {
         res = (res * base) % q;
      }
      return res;
   };

   auto csubq = [q](T a) -> T { return a <= q / 2 ? a : a - q; };

   for(size_t i = 0; i < result.size(); ++i) {
      result[i] = csubq(pow(root_of_unity, bitreverse(i)) * monty % q);
   }

   return result;
}

namespace detail {

/**
 * Wraps any XOF to limit the number of bytes that can be produced to @p bound.
 * When the bound is reached, the XOF will throw an Internal_Error.
 */
template <typename XofT, size_t bound>
   requires requires(XofT xof) {
      { xof.template output<1>() } -> std::convertible_to<std::span<const uint8_t, 1>>;
      { xof.template output<42>() } -> std::convertible_to<std::span<const uint8_t, 42>>;
   }
class Bounded_XOF final {
   private:
      template <size_t bytes, typename MapFnT>
      using MappedValueT = std::invoke_result_t<MapFnT, std::array<uint8_t, bytes>>;

   public:
      template <size_t bytes>
      constexpr static auto default_transformer(std::array<uint8_t, bytes> x) {
         return x;
      }

      template <size_t bytes, typename T>
      constexpr static bool default_predicate(T) {
         return true;
      }

   public:
      Bounded_XOF()
         requires std::default_initializable<XofT>
            : m_bytes_consumed(0) {}

      explicit Bounded_XOF(XofT xof) : m_xof(xof), m_bytes_consumed(0) {}

      /**
       * @returns the next byte from the XOF that fulfills @p predicate.
       */
      template <typename PredicateFnT = decltype(default_predicate<1, uint8_t>)>
         requires std::invocable<PredicateFnT, uint8_t>
      constexpr auto next_byte(PredicateFnT&& predicate = default_predicate<1, uint8_t>) {
         return next<1>([](const auto bytes) { return bytes[0]; }, std::forward<PredicateFnT>(predicate));
      }

      /**
       * Pulls the next @p bytes from the XOF and applies @p transformer to the
       * output. The result is returned if @p predicate is fulfilled.
       * @returns the transformed output of the XOF that fulfills @p predicate.
       */
      template <size_t bytes,
                typename MapFnT = decltype(default_transformer<bytes>),
                typename PredicateFnT = decltype(default_predicate<bytes, MappedValueT<bytes, MapFnT>>)>
         requires std::invocable<MapFnT, std::array<uint8_t, bytes>> &&
                  std::invocable<PredicateFnT, MappedValueT<bytes, MapFnT>>
      constexpr auto next(MapFnT&& transformer = default_transformer<bytes>,
                          PredicateFnT&& predicate = default_predicate<bytes, MappedValueT<bytes, MapFnT>>) {
         while(true) {
            auto output = transformer(take<bytes>());
            if(predicate(output)) {
               return output;
            }
         }
      }

   private:
      template <size_t bytes>
      constexpr std::array<uint8_t, bytes> take() {
         m_bytes_consumed += bytes;
         if(m_bytes_consumed > bound) {
            throw Internal_Error("XOF consumed more bytes than allowed");
         }
         return m_xof.template output<bytes>();
      }

   private:
      XofT m_xof;
      size_t m_bytes_consumed;
};

}  // namespace detail

class XOF;

template <size_t bound>
using Bounded_XOF = detail::Bounded_XOF<XOF&, bound>;

}  // namespace Botan

#endif

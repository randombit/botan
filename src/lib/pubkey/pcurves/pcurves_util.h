/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_UTIL_H_
#define BOTAN_PCURVES_UTIL_H_

#include <botan/internal/mp_core.h>
#include <array>

namespace Botan {

template <WordType W, size_t N, size_t XN>
inline consteval std::array<W, N> reduce_mod(const std::array<W, XN>& x, const std::array<W, N>& p) {
   std::array<W, N + 1> r = {0};
   std::array<W, N + 1> t = {0};

   const size_t x_bits = XN * WordInfo<W>::bits;

   for(size_t i = 0; i != x_bits; ++i) {
      const size_t b = x_bits - 1 - i;

      const size_t b_word = b / WordInfo<W>::bits;
      const size_t b_bit = b % WordInfo<W>::bits;
      const bool x_b = (x[b_word] >> b_bit) & 1;

      shift_left<1>(r);
      if(x_b) {
         r[0] += 1;
      }

      const W carry = bigint_sub3(t.data(), r.data(), N + 1, p.data(), N);

      if(carry == 0) {
         std::swap(r, t);
      }
   }

   std::array<W, N> rs;
   std::copy(r.begin(), r.begin() + N, rs.begin());
   return rs;
}

template <WordType W, size_t N>
inline consteval std::array<W, N> montygomery_r(const std::array<W, N>& p) {
   std::array<W, N + 1> x = {0};
   x[N] = 1;
   return reduce_mod(x, p);
}

template <WordType W, size_t N>
inline consteval std::array<W, N> mul_mod(const std::array<W, N>& x,
                                          const std::array<W, N>& y,
                                          const std::array<W, N>& p) {
   std::array<W, 2 * N> z;
   comba_mul<N>(z.data(), x.data(), y.data());
   return reduce_mod(z, p);
}

template <WordType W, size_t N, size_t ZL>
inline constexpr auto bigint_monty_redc(const std::array<W, ZL>& z, const std::array<W, N>& p, word p_dash)
   -> std::array<W, N> {
   static_assert(N >= 1);
   static_assert(ZL <= 2 * N);

   std::array<W, N> ws;

   W w2 = 0, w1 = 0, w0 = 0;

   w0 = z[0];

   ws[0] = w0 * p_dash;

   word3_muladd(&w2, &w1, &w0, ws[0], p[0]);

   w0 = w1;
   w1 = w2;
   w2 = 0;

   for(size_t i = 1; i != N; ++i) {
      for(size_t j = 0; j < i; ++j) {
         word3_muladd(&w2, &w1, &w0, ws[j], p[i - j]);
      }

      word3_add(&w2, &w1, &w0, i < ZL ? z[i] : 0);

      ws[i] = w0 * p_dash;

      word3_muladd(&w2, &w1, &w0, ws[i], p[0]);

      w0 = w1;
      w1 = w2;
      w2 = 0;
   }

   for(size_t i = 0; i != N - 1; ++i) {
      for(size_t j = i + 1; j != N; ++j) {
         word3_muladd(&w2, &w1, &w0, ws[j], p[N + i - j]);
      }

      word3_add(&w2, &w1, &w0, N + i < ZL ? z[N + i] : 0);

      ws[i] = w0;

      w0 = w1;
      w1 = w2;
      w2 = 0;
   }

   word3_add(&w2, &w1, &w0, (2 * N - 1) < ZL ? z[2 * N - 1] : 0);

   ws[N - 1] = w0;

   std::array<W, N> r = {0};
   for(size_t i = 0; i != std::min(ZL, N); ++i) {
      r[i] = z[i];
   }
   bigint_monty_maybe_sub<N>(r.data(), w1, ws.data(), p.data());

   return r;
}

template <uint8_t X, WordType W, size_t N>
inline consteval std::array<W, N> p_minus(const std::array<W, N>& p) {
   // TODO combine into p_plus_x_over_y<-1, 1>
   static_assert(X > 0);
   std::array<W, N> r;
   W x = X;
   bigint_sub3(r.data(), p.data(), N, &x, 1);
   return r;
}

template <WordType W, size_t N>
inline consteval std::array<W, N> p_plus_1_over_4(const std::array<W, N>& p) {
   const W one = 1;
   std::array<W, N> r;
   bigint_add3_nc(r.data(), p.data(), N, &one, 1);
   shift_right<2>(r);
   return r;
}

template <WordType W, size_t N>
inline consteval std::array<W, N> p_minus_1_over_2(const std::array<W, N>& p) {
   const W one = 1;
   std::array<W, N> r;
   bigint_sub3(r.data(), p.data(), N, &one, 1);
   shift_right<1>(r);
   return r;
}

template <WordType W, size_t N>
inline constexpr uint8_t get_bit(size_t i, const std::array<W, N>& p) {
   const size_t w = i / WordInfo<W>::bits;
   const size_t b = i % WordInfo<W>::bits;

   return static_cast<uint8_t>((p[w] >> b) & 0x01);
}

template <WordType W, size_t N>
inline consteval size_t count_bits(const std::array<W, N>& p) {
   size_t b = WordInfo<W>::bits * N;

   while(get_bit(b - 1, p) == 0) {
      b -= 1;
   }

   return b;
}

template <WordType W, size_t N, size_t L>
inline constexpr auto bytes_to_words(const uint8_t bytes[L]) {
   static_assert(L <= WordInfo<W>::bytes * N);

   std::array<W, N> r = {};
   for(size_t i = 0; i != L; ++i) {
      shift_left<8>(r);
      r[0] += bytes[i];
   }
   return r;
}

}  // namespace Botan

#endif

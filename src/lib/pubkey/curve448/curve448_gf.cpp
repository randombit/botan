/*
* X448 Gf Modulo 2^448 - 2^224 - 1
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/internal/curve448_gf.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mp_asmi.h>
#include <botan/internal/mp_core.h>

#include <algorithm>

namespace Botan {

namespace {

/**
 * @brief Compute (a + b). The carry is returned in the carry parameter.
 *  The carry is not included for the addition.
 */
inline uint64_t u64_add(uint64_t a, uint64_t b, bool* carry) {
   // Let the compiler optimize this into fancy instructions
   const uint64_t sum = a + b;
   *carry = sum < a;
   return sum;
}

/**
 * @brief Compute (a + b + carry), where carry is in {0, 1}. The carry of this computation
 * is store in the in/out @p carry parameter.
 */
inline uint64_t u64_add_with_carry(uint64_t a, uint64_t b, bool* carry) {
   // Let the compiler optimize this into fancy instructions
   uint64_t sum = a + b;
   const bool carry_a_plus_b = (sum < a);
   sum += static_cast<uint64_t>(*carry);
   *carry = static_cast<uint64_t>(carry_a_plus_b) | static_cast<uint64_t>(sum < static_cast<uint64_t>(*carry));
   return sum;
}

/**
 * @brief Compute (a - (b + borrow)). The borrow is returned in the carry parameter.
 *
 * I.e. borrow = 1 if a < b + borrow, else 0.
 */
inline uint64_t u64_sub_with_borrow(uint64_t a, uint64_t b, bool* borrow) {
   // Let the compiler optimize this into fancy instructions
   const uint64_t diff = a - b;
   const bool borrow_a_min_b = diff > a;
   const uint64_t z = diff - static_cast<uint64_t>(*borrow);
   *borrow = static_cast<uint64_t>(borrow_a_min_b) | static_cast<uint64_t>(z > diff);
   return z;
}

/**
 * @brief Reduce the result of a addition modulo 2^448 - 2^224 - 1.
 *
 * Algorithm 1 of paper "Reduction Modulo 2^448 - 2^224 - 1", from line 27.
 *
 * @param h_3 Output
 * @param h_1 Input
 */
void reduce_after_add(std::span<uint64_t, WORDS_448> h_3, std::span<const uint64_t, 8> h_1) {
   std::array<uint64_t, 8> h_2;
   bool carry;

   // Line 27+ (of the paper's algorithm 1)
   h_2[0] = u64_add(h_1[0], h_1[7], &carry);

   h_2[1] = u64_add(h_1[1], carry, &carry);
   h_2[2] = u64_add(h_1[2], carry, &carry);

   // Line 30
   h_2[3] = u64_add_with_carry(h_1[3], h_1[7] << 32, &carry);

   // Line 31+
   h_2[4] = u64_add(h_1[4], carry, &carry);
   h_2[5] = u64_add(h_1[5], carry, &carry);
   h_2[6] = u64_add(h_1[6], carry, &carry);

   h_2[7] = carry;

   h_3[0] = u64_add(h_2[0], h_2[7], &carry);
   h_3[1] = u64_add(h_2[1], carry, &carry);
   h_3[2] = u64_add(h_2[2], carry, &carry);
   // Line 37
   h_3[3] = h_2[3] + (h_2[7] << 32) + carry;

   // Line 38
   h_3[4] = h_2[4];
   h_3[5] = h_2[5];
   h_3[6] = h_2[6];
}

/**
 * @brief Reduce the result of a addition modulo 2^448 - 2^224 - 1.
 *
 * Algorithm 1 of paper "Reduction Modulo 2^448 - 2^224 - 1".
 */
void reduce_after_mul(std::span<uint64_t, WORDS_448> out, std::span<const uint64_t, 14> in) {
   std::array<uint64_t, 8> r;
   std::array<uint64_t, 8> s;
   std::array<uint64_t, 8> t_0;
   std::array<uint64_t, 8> h_1;

   bool carry;

   // Line 4 (of the paper's algorithm 1)
   r[0] = u64_add(in[0], in[7], &carry);

   // Line 5-7
   for(size_t i = 1; i < 7; ++i) {
      r[i] = u64_add_with_carry(in[i], in[i + 7], &carry);
   }
   r[7] = carry;
   s[0] = r[0];
   s[1] = r[1];
   s[2] = r[2];
   // Line 10
   s[3] = u64_add(r[3], in[10] & 0xFFFFFFFF00000000, &carry);
   // Line 11-13
   for(size_t i = 4; i < 7; ++i) {
      s[i] = u64_add_with_carry(r[i], in[i + 7], &carry);
   }
   s[7] = r[7] + carry;

   // Line 15-17
   for(size_t i = 0; i < 3; ++i) {
      t_0[i] = (in[i + 11] << 32) | (in[i + 10] >> 32);
   }
   // Line 18
   t_0[3] = (in[7] << 32) | (in[13] >> 32);
   // Line 19-21
   for(size_t i = 4; i < 7; ++i) {
      t_0[i] = (in[i + 4] << 32) | (in[i + 3] >> 32);
   }
   h_1[0] = u64_add(s[0], t_0[0], &carry);
   // Line 23-25
   for(size_t i = 1; i < 7; ++i) {
      h_1[i] = u64_add_with_carry(s[i], t_0[i], &carry);
   }
   h_1[7] = s[7] + carry;

   reduce_after_add(out, h_1);
}

void gf_mul(std::span<uint64_t, WORDS_448> out,
            std::span<const uint64_t, WORDS_448> a,
            std::span<const uint64_t, WORDS_448> b) {
   std::array<uint64_t, 14> ws;
   comba_mul<7>(ws.data(), a.data(), b.data());
   reduce_after_mul(out, ws);
}

void gf_square(std::span<uint64_t, WORDS_448> out, std::span<const uint64_t, WORDS_448> a) {
   std::array<uint64_t, 14> ws;
   comba_sqr<7>(ws.data(), a.data());
   reduce_after_mul(out, ws);
}

void gf_add(std::span<uint64_t, WORDS_448> out,
            std::span<const uint64_t, WORDS_448> a,
            std::span<const uint64_t, WORDS_448> b) {
   std::array<uint64_t, WORDS_448 + 1> ws;
   copy_mem(std::span(ws).first<WORDS_448>(), a);
   ws[WORDS_448] = 0;

   bool carry = false;
   for(size_t i = 0; i < WORDS_448; ++i) {
      ws[i] = u64_add_with_carry(a[i], b[i], &carry);
   }
   ws[WORDS_448] = carry;

   reduce_after_add(out, ws);
}

/**
 * @brief Subtract two elements in GF(P). out = a - b
 *
 * Algorithm 2 of paper: "Reduction Modulo 2^448 - 2^224 - 1"
 */
void gf_sub(std::span<uint64_t, WORDS_448> out,
            std::span<const uint64_t, WORDS_448> a,
            std::span<const uint64_t, WORDS_448> b) {
   std::array<uint64_t, WORDS_448> h_0;
   std::array<uint64_t, WORDS_448> h_1;

   bool borrow = false;
   for(size_t i = 0; i < WORDS_448; ++i) {
      h_0[i] = u64_sub_with_borrow(a[i], b[i], &borrow);
   }
   uint64_t delta = borrow;
   uint64_t delta_p = delta << 32;
   borrow = false;

   h_1[0] = u64_sub_with_borrow(h_0[0], delta, &borrow);
   h_1[1] = u64_sub_with_borrow(h_0[1], 0, &borrow);
   h_1[2] = u64_sub_with_borrow(h_0[2], 0, &borrow);
   h_1[3] = u64_sub_with_borrow(h_0[3], delta_p, &borrow);
   h_1[4] = u64_sub_with_borrow(h_0[4], 0, &borrow);
   h_1[5] = u64_sub_with_borrow(h_0[5], 0, &borrow);
   h_1[6] = u64_sub_with_borrow(h_0[6], 0, &borrow);

   delta = borrow;
   delta_p = delta << 32;
   borrow = false;

   out[0] = u64_sub_with_borrow(h_1[0], delta, &borrow);
   out[1] = u64_sub_with_borrow(h_1[1], 0, &borrow);
   out[2] = u64_sub_with_borrow(h_1[2], 0, &borrow);
   out[3] = u64_sub_with_borrow(h_1[3], delta_p, &borrow);
   out[4] = h_1[4];
   out[5] = h_1[5];
   out[6] = h_1[6];
}

/**
 * @brief Inversion in GF(P) using Fermat's little theorem:
 * x^-1 = x^(P-2) mod P
 */
void gf_inv(std::span<uint64_t, WORDS_448> out, std::span<const uint64_t, WORDS_448> a) {
   clear_mem(out);
   out[0] = 1;
   // Square and multiply
   for(int16_t t = 448; t >= 0; --t) {
      gf_square(out, out);
      // (P-2) has zero bits at indices 1, 224, 448. All others are one.
      if(t != 448 && t != 224 && t != 1) {
         gf_mul(out, out, a);
      }
   }
}

/**
 * @brief Convert a number to its canonical representation.
 *
 * I.e. if the number is greater than P, subtract P. The number cannot be >= 2P
 * since 2*P > 2^(7*64).
 */
std::array<uint64_t, WORDS_448> to_canonical(std::span<const uint64_t, WORDS_448> in) {
   const std::array<uint64_t, WORDS_448> p = {0xffffffffffffffff,
                                              0xffffffffffffffff,
                                              0xffffffffffffffff,
                                              0xfffffffeffffffff,
                                              0xffffffffffffffff,
                                              0xffffffffffffffff,
                                              0xffffffffffffffff};

   std::array<uint64_t, WORDS_448> in_minus_p;
   bool borrow = false;
   for(size_t i = 0; i < WORDS_448; ++i) {
      in_minus_p[i] = u64_sub_with_borrow(in[i], p[i], &borrow);
   }
   std::array<uint64_t, WORDS_448> out;
   CT::Mask<uint64_t>::expand(borrow).select_n(out.data(), in.data(), in_minus_p.data(), WORDS_448);
   return out;
}

}  // namespace

Gf448Elem::Gf448Elem(std::span<const uint8_t, BYTES_448> x) {
   load_le(m_x, x);
}

Gf448Elem::Gf448Elem(uint64_t least_sig_word) {
   clear_mem(m_x);
   m_x[0] = least_sig_word;
}

void Gf448Elem::to_bytes(std::span<uint8_t, BYTES_448> out) const {
   store_le(out, to_canonical(m_x));
}

std::array<uint8_t, BYTES_448> Gf448Elem::to_bytes() const {
   std::array<uint8_t, BYTES_448> bytes;
   to_bytes(bytes);
   return bytes;
}

void Gf448Elem::ct_cond_swap(bool b, Gf448Elem& other) {
   for(size_t i = 0; i < WORDS_448; ++i) {
      CT::conditional_swap(b, m_x[i], other.m_x[i]);
   }
}

void Gf448Elem::ct_cond_assign(bool b, const Gf448Elem& other) {
   CT::conditional_assign_mem(static_cast<uint64_t>(b), m_x.data(), other.m_x.data(), WORDS_448);
}

Gf448Elem Gf448Elem::operator+(const Gf448Elem& other) const {
   Gf448Elem res(0);
   gf_add(res.m_x, m_x, other.m_x);
   return res;
}

Gf448Elem Gf448Elem::operator-(const Gf448Elem& other) const {
   Gf448Elem res(0);
   gf_sub(res.m_x, m_x, other.m_x);
   return res;
}

Gf448Elem Gf448Elem::operator-() const {
   Gf448Elem res(0);
   gf_sub(res.m_x, res.m_x, m_x);
   return res;
}

Gf448Elem Gf448Elem::operator*(const Gf448Elem& other) const {
   Gf448Elem res(0);
   gf_mul(res.m_x, m_x, other.m_x);
   return res;
}

Gf448Elem Gf448Elem::operator/(const Gf448Elem& other) const {
   Gf448Elem res(0);
   gf_inv(res.m_x, other.m_x);
   gf_mul(res.m_x, m_x, res.m_x);
   return res;
}

bool Gf448Elem::operator==(const Gf448Elem& other) const {
   const auto canonical_form_this = to_canonical(m_x);
   const auto canonical_form_other = to_canonical(other.m_x);
   return CT::is_equal(canonical_form_this.data(), canonical_form_other.data(), WORDS_448).as_bool();
}

bool Gf448Elem::is_zero() const {
   const auto canonical_form = to_canonical(m_x);

   return CT::all_zeros(canonical_form.data(), WORDS_448).as_bool();
}

bool Gf448Elem::is_odd() const {
   const auto canonical_form = to_canonical(m_x);
   return (canonical_form[0] & 1) == 1;
}

bool Gf448Elem::bytes_are_canonical_representation(std::span<const uint8_t, BYTES_448> x) {
   const auto x_words = load_le<std::array<uint64_t, WORDS_448>>(x);
   const auto x_words_canonical = to_canonical(x_words);
   return CT::is_equal(x_words.data(), x_words_canonical.data(), WORDS_448).as_bool();
}

Gf448Elem square(const Gf448Elem& elem) {
   Gf448Elem res(0);
   gf_square(res.words(), elem.words());
   return res;
}

Gf448Elem root(const Gf448Elem& elem) {
   Gf448Elem res(1);

   // (P-3)/4 is an 445 bit integer with one zero bits at 222. All others are one.
   for(int16_t t = 445; t >= 0; --t) {
      gf_square(res.words(), res.words());
      if(t != 222) {
         gf_mul(res.words(), res.words(), elem.words());
      }
   }

   return res;
}

}  // namespace Botan

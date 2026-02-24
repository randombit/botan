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

namespace Botan {

namespace {

/**
 * @brief Reduce the result of a addition modulo 2^448 - 2^224 - 1.
 *
 * Algorithm 1 of paper "Reduction Modulo 2^448 - 2^224 - 1", from line 27.
 *
 * @param h_3 Output
 * @param h_1 Input
 */
void reduce_after_add(std::span<uint64_t, WORDS_448> h_3, std::span<const uint64_t, 8> h_1) {
   std::array<uint64_t, 8> h_2; /* NOLINT(*-member-init) */
   uint64_t carry = 0;

   constexpr uint64_t zero = 0;

   // Line 27+ (of the paper's algorithm 1)
   h_2[0] = word_add(h_1[0], h_1[7], &carry);
   h_2[1] = word_add(h_1[1], zero, &carry);
   h_2[2] = word_add(h_1[2], zero, &carry);

   // Line 30
   h_2[3] = word_add(h_1[3], h_1[7] << 32, &carry);

   // Line 31+
   h_2[4] = word_add(h_1[4], zero, &carry);
   h_2[5] = word_add(h_1[5], zero, &carry);
   h_2[6] = word_add(h_1[6], zero, &carry);

   h_2[7] = carry;

   carry = 0;
   h_3[0] = word_add(h_2[0], h_2[7], &carry);
   h_3[1] = word_add(h_2[1], zero, &carry);
   h_3[2] = word_add(h_2[2], zero, &carry);
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
   std::array<uint64_t, 8> r;    // NOLINT(*-member-init)
   std::array<uint64_t, 8> s;    // NOLINT(*-member-init)
   std::array<uint64_t, 8> t_0;  // NOLINT(*-member-init)
   std::array<uint64_t, 8> h_1;  // NOLINT(*-member-init)

   uint64_t carry = 0;

   // Line 4 (of the paper's algorithm 1)
   r[0] = word_add(in[0], in[7], &carry);

   // Line 5-7
   r[1] = word_add(in[1], in[1 + 7], &carry);
   r[2] = word_add(in[2], in[2 + 7], &carry);
   r[3] = word_add(in[3], in[3 + 7], &carry);
   r[4] = word_add(in[4], in[4 + 7], &carry);
   r[5] = word_add(in[5], in[5 + 7], &carry);
   r[6] = word_add(in[6], in[6 + 7], &carry);
   r[7] = carry;
   s[0] = r[0];
   s[1] = r[1];
   s[2] = r[2];
   // Line 10
   carry = 0;
   s[3] = word_add(r[3], in[10] & 0xFFFFFFFF00000000, &carry);
   // Line 11-13
   s[4] = word_add(r[4], in[4 + 7], &carry);
   s[5] = word_add(r[5], in[5 + 7], &carry);
   s[6] = word_add(r[6], in[6 + 7], &carry);
   s[7] = r[7] + carry;

   // Line 15-17
   t_0[0] = (in[0 + 11] << 32) | (in[0 + 10] >> 32);
   t_0[1] = (in[1 + 11] << 32) | (in[1 + 10] >> 32);
   t_0[2] = (in[2 + 11] << 32) | (in[2 + 10] >> 32);
   // Line 18
   t_0[3] = (in[7] << 32) | (in[13] >> 32);
   // Line 19-21
   t_0[4] = (in[4 + 4] << 32) | (in[4 + 3] >> 32);
   t_0[5] = (in[5 + 4] << 32) | (in[5 + 3] >> 32);
   t_0[6] = (in[6 + 4] << 32) | (in[6 + 3] >> 32);
   carry = 0;
   // Line 23-25
   h_1[0] = word_add(s[0], t_0[0], &carry);
   h_1[1] = word_add(s[1], t_0[1], &carry);
   h_1[2] = word_add(s[2], t_0[2], &carry);
   h_1[3] = word_add(s[3], t_0[3], &carry);
   h_1[4] = word_add(s[4], t_0[4], &carry);
   h_1[5] = word_add(s[5], t_0[5], &carry);
   h_1[6] = word_add(s[6], t_0[6], &carry);
   h_1[7] = s[7] + carry;

   reduce_after_add(out, h_1);
}

// Multiply by the Curve448 constant a24 = (a-2)/4 = 39081.
// Uses a 7-word × 1-word multiply (7 muls vs 49 for full comba_mul<7>),
// and the result fits in 8 words so only needs reduce_after_add.
void gf_mul_a24(std::span<uint64_t, WORDS_448> out, std::span<const uint64_t, WORDS_448> a) {
   constexpr uint64_t A24 = 39081;
   std::array<uint64_t, 8> ws;  // NOLINT(*-member-init)
   uint64_t carry = 0;
   ws[0] = word_madd2(a[0], A24, &carry);
   ws[1] = word_madd2(a[1], A24, &carry);
   ws[2] = word_madd2(a[2], A24, &carry);
   ws[3] = word_madd2(a[3], A24, &carry);
   ws[4] = word_madd2(a[4], A24, &carry);
   ws[5] = word_madd2(a[5], A24, &carry);
   ws[6] = word_madd2(a[6], A24, &carry);
   ws[7] = carry;
   reduce_after_add(out, ws);
}

void gf_mul(std::span<uint64_t, WORDS_448> out,
            std::span<const uint64_t, WORDS_448> a,
            std::span<const uint64_t, WORDS_448> b) {
   std::array<uint64_t, 14> ws;  // NOLINT(*-member-init)
   comba_mul<7>(ws.data(), a.data(), b.data());
   reduce_after_mul(out, ws);
}

void gf_square(std::span<uint64_t, WORDS_448> out, std::span<const uint64_t, WORDS_448> a) {
   std::array<uint64_t, 14> ws;  // NOLINT(*-member-init)
   comba_sqr<7>(ws.data(), a.data());
   reduce_after_mul(out, ws);
}

void gf_add(std::span<uint64_t, WORDS_448> out,
            std::span<const uint64_t, WORDS_448> a,
            std::span<const uint64_t, WORDS_448> b) {
   std::array<uint64_t, WORDS_448 + 1> ws;  // NOLINT(*-member-init)

   uint64_t carry = 0;
   ws[0] = word_add(a[0], b[0], &carry);
   ws[1] = word_add(a[1], b[1], &carry);
   ws[2] = word_add(a[2], b[2], &carry);
   ws[3] = word_add(a[3], b[3], &carry);
   ws[4] = word_add(a[4], b[4], &carry);
   ws[5] = word_add(a[5], b[5], &carry);
   ws[6] = word_add(a[6], b[6], &carry);
   ws[7] = carry;

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
   std::array<uint64_t, WORDS_448> h_0;  // NOLINT(*-member-init)
   std::array<uint64_t, WORDS_448> h_1;  // NOLINT(*-member-init)

   uint64_t borrow = 0;
   h_0[0] = word_sub(a[0], b[0], &borrow);
   h_0[1] = word_sub(a[1], b[1], &borrow);
   h_0[2] = word_sub(a[2], b[2], &borrow);
   h_0[3] = word_sub(a[3], b[3], &borrow);
   h_0[4] = word_sub(a[4], b[4], &borrow);
   h_0[5] = word_sub(a[5], b[5], &borrow);
   h_0[6] = word_sub(a[6], b[6], &borrow);
   uint64_t delta = borrow;
   uint64_t delta_p = delta << 32;
   borrow = 0;

   constexpr uint64_t zero = 0;

   h_1[0] = word_sub(h_0[0], delta, &borrow);
   h_1[1] = word_sub(h_0[1], zero, &borrow);
   h_1[2] = word_sub(h_0[2], zero, &borrow);
   h_1[3] = word_sub(h_0[3], delta_p, &borrow);
   h_1[4] = word_sub(h_0[4], zero, &borrow);
   h_1[5] = word_sub(h_0[5], zero, &borrow);
   h_1[6] = word_sub(h_0[6], zero, &borrow);

   delta = borrow;
   delta_p = delta << 32;
   borrow = 0;

   out[0] = word_sub(h_1[0], delta, &borrow);
   out[1] = word_sub(h_1[1], zero, &borrow);
   out[2] = word_sub(h_1[2], zero, &borrow);
   out[3] = word_sub(h_1[3], delta_p, &borrow);
   out[4] = h_1[4];
   out[5] = h_1[5];
   out[6] = h_1[6];
}

/// Square a field element n times
void gf_sqr_n(std::span<uint64_t, WORDS_448> out, std::span<const uint64_t, WORDS_448> a, size_t n) {
   gf_square(out, a);
   for(size_t i = 1; i < n; ++i) {
      gf_square(out, out);
   }
}

/**
 * @brief Compute x^(2^222 - 1) using an addition chain.
 *
 * This is the shared prefix of the addition chains for both
 * inversion (x^(p-2)) and square root (x^((p-3)/4)).
 *
 * Addition chain from addchain tool (cost 446):
 *   _11     = 1 + _10
 *   _111    = 1 + _110
 *   _111111 = _111 + _111 << 3
 *   x12     = _111111 << 6 + _111111
 *   x24     = x12 << 12 + x12
 *   x30     = _111111 + x24 << 6
 *   x48     = x24 << 6 << 18 + x24
 *   x96     = x48 << 48 + x48
 *   x192    = x96 << 96 + x96
 *   x222    = x192 << 30 + x30
 */
void gf_pow_2_222m1(std::span<uint64_t, WORDS_448> x222,
                    std::span<uint64_t, WORDS_448> x223,
                    std::span<const uint64_t, WORDS_448> a) {
   std::array<uint64_t, WORDS_448> t;  // NOLINT(*-member-init)

   // _10 = a^2
   std::array<uint64_t, WORDS_448> a2;  // NOLINT(*-member-init)
   gf_square(a2, a);

   // _11 = a^3
   std::array<uint64_t, WORDS_448> a3;  // NOLINT(*-member-init)
   gf_mul(a3, a, a2);

   // _111 = a^7
   std::array<uint64_t, WORDS_448> a7;  // NOLINT(*-member-init)
   gf_square(t, a3);
   gf_mul(a7, a, t);

   // _111111 = a^63
   std::array<uint64_t, WORDS_448> a63;  // NOLINT(*-member-init)
   gf_sqr_n(t, a7, 3);
   gf_mul(a63, a7, t);

   // x12 = a^(2^12 - 1)
   std::array<uint64_t, WORDS_448> x12;  // NOLINT(*-member-init)
   gf_sqr_n(t, a63, 6);
   gf_mul(x12, a63, t);

   // x24 = a^(2^24 - 1)
   std::array<uint64_t, WORDS_448> x24;  // NOLINT(*-member-init)
   gf_sqr_n(t, x12, 12);
   gf_mul(x24, x12, t);

   // i34 = x24 << 6 = a^((2^24 - 1) * 2^6)
   std::array<uint64_t, WORDS_448> i34;  // NOLINT(*-member-init)
   gf_sqr_n(i34, x24, 6);

   // x30 = a^(2^30 - 1)
   std::array<uint64_t, WORDS_448> x30;  // NOLINT(*-member-init)
   gf_mul(x30, a63, i34);

   // x48 = a^(2^48 - 1)
   std::array<uint64_t, WORDS_448> x48;  // NOLINT(*-member-init)
   gf_sqr_n(t, i34, 18);
   gf_mul(x48, x24, t);

   // x96 = a^(2^96 - 1)
   std::array<uint64_t, WORDS_448> x96;  // NOLINT(*-member-init)
   gf_sqr_n(t, x48, 48);
   gf_mul(x96, x48, t);

   // x192 = a^(2^192 - 1)
   std::array<uint64_t, WORDS_448> x192;  // NOLINT(*-member-init)
   gf_sqr_n(t, x96, 96);
   gf_mul(x192, x96, t);

   // x222 = a^(2^222 - 1)
   gf_sqr_n(t, x192, 30);
   gf_mul(x222, x30, t);

   // x223 = a^(2^223 - 1)
   gf_square(t, x222);
   gf_mul(x223, a, t);
}

/**
 * @brief Inversion in GF(P) using Fermat's little theorem:
 * x^-1 = x^(P-2) mod P
 *
 * Uses an optimized addition chain (cost 460) found by addchain.
 * P-2 = 2^448 - 2^224 - 3
 * return = (x223 << 223 + x222) << 2 + 1
 */
void gf_inv(std::span<uint64_t, WORDS_448> out, std::span<const uint64_t, WORDS_448> a) {
   std::array<uint64_t, WORDS_448> x222;  // NOLINT(*-member-init)
   std::array<uint64_t, WORDS_448> x223;  // NOLINT(*-member-init)
   gf_pow_2_222m1(x222, x223, a);

   // (x223 << 223 + x222) << 2 + 1
   std::array<uint64_t, WORDS_448> t;  // NOLINT(*-member-init)
   gf_sqr_n(t, x223, 223);
   gf_mul(t, t, x222);
   gf_sqr_n(t, t, 2);
   gf_mul(out, t, a);
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

   std::array<uint64_t, WORDS_448> in_minus_p;  // NOLINT(*-member-init)
   uint64_t borrow = 0;
   for(size_t i = 0; i < WORDS_448; ++i) {
      in_minus_p[i] = word_sub(in[i], p[i], &borrow);
   }
   std::array<uint64_t, WORDS_448> out;  // NOLINT(*-member-init)
   CT::Mask<uint64_t>::expand(borrow).select_n(out.data(), in.data(), in_minus_p.data(), WORDS_448);
   return out;
}

}  // namespace

Gf448Elem::Gf448Elem(std::span<const uint8_t, BYTES_448> x) /* NOLINT(*-member-init) */ {
   load_le(m_x, x);
}

Gf448Elem::Gf448Elem(uint64_t least_sig_word) /* NOLINT(*-member-init) */ {
   clear_mem(m_x);
   m_x[0] = least_sig_word;
}

void Gf448Elem::to_bytes(std::span<uint8_t, BYTES_448> out) const {
   store_le(out, to_canonical(m_x));
}

std::array<uint8_t, BYTES_448> Gf448Elem::to_bytes() const {
   std::array<uint8_t, BYTES_448> bytes{};
   to_bytes(bytes);
   return bytes;
}

void Gf448Elem::ct_cond_swap(CT::Mask<uint64_t> mask, Gf448Elem& other) {
   for(size_t i = 0; i < WORDS_448; ++i) {
      mask.conditional_swap(m_x[i], other.m_x[i]);
   }
}

void Gf448Elem::ct_cond_assign(CT::Mask<uint64_t> mask, const Gf448Elem& other) {
   mask.select_n(m_x.data(), other.m_x.data(), m_x.data(), WORDS_448);
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

Gf448Elem mul_a24(const Gf448Elem& a) {
   Gf448Elem res(0);
   gf_mul_a24(res.words(), a.words());
   return res;
}

Gf448Elem square(const Gf448Elem& elem) {
   Gf448Elem res(0);
   gf_square(res.words(), elem.words());
   return res;
}

Gf448Elem root(const Gf448Elem& elem) {
   // Compute elem^((P-3)/4) using an optimized addition chain (cost 457).
   // (P-3)/4 = 2^446 - 2^222 - 1
   // return = x223 << 223 + x222
   std::array<uint64_t, WORDS_448> x222;  // NOLINT(*-member-init)
   std::array<uint64_t, WORDS_448> x223;  // NOLINT(*-member-init)
   gf_pow_2_222m1(x222, x223, elem.words());

   Gf448Elem res(0);
   gf_sqr_n(res.words(), x223, 223);
   gf_mul(res.words(), res.words(), x222);
   return res;
}

}  // namespace Botan

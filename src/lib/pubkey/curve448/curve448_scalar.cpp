/*
 * Ed448 Scalar
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */
#include <botan/internal/curve448_scalar.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>

namespace Botan {

namespace {
constexpr size_t WORDS_REDUCE_SZ = words_for_bits(114 * 8);
constexpr size_t WORDS_C = words_for_bits(28 * 8);

/// @return (q,r) so that x = q*2^446 + r, r < L
template <size_t S>
auto div_mod_2_446(std::span<const word, S> x) {
   if constexpr(S < Scalar448::WORDS) {
      std::array<word, Scalar448::WORDS> r = {0};
      copy_mem(std::span(r).template first<S>(), x);
      return std::make_pair(std::array<word, 1>({0}), r);
   } else {
      std::array<word, Scalar448::WORDS> r;
      copy_mem(r, std::span(x).template first<Scalar448::WORDS>());
      // Clear the two most significant bits
      r[Scalar448::WORDS - 1] &= ~(word(0b11) << (sizeof(word) * 8 - 2));

      std::array<word, S - Scalar448::WORDS + 1> q;
      bigint_shr2(q.data(), x.data(), x.size(), 446);

      return std::make_pair(q, r);
   }
}

/// @return a word array for c = 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
consteval std::array<word, WORDS_C> c_words() {
   const std::array<uint8_t, WORDS_C * sizeof(word)> c_bytes{0x0d, 0xbb, 0xa7, 0x54, 0x6d, 0x3d, 0x87, 0xdc, 0xaa, 0x70,
                                                             0x3a, 0x72, 0x8d, 0x3d, 0x93, 0xde, 0x6f, 0xc9, 0x29, 0x51,
                                                             0xb6, 0x24, 0xb1, 0x3b, 0x16, 0xdc, 0x35, 0x83};
   return load_le<std::array<word, WORDS_C>>(c_bytes);
}

/// @return a word array for L = 2^446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
consteval std::array<word, Scalar448::WORDS> big_l_words() {
   const std::array<uint8_t, Scalar448::WORDS * sizeof(word)> big_l_bytes{
      0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21, 0x90, 0x36, 0xd6,
      0xae, 0x49, 0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f};
   return load_le<std::array<word, Scalar448::WORDS>>(big_l_bytes);
}

/// @return c*x, with c = 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
template <size_t S>
std::array<word, S + WORDS_C> mul_c(std::span<const word, S> x) {
   std::array<word, S + WORDS_C> res;
   std::array<word, S + WORDS_C> ws;
   constexpr std::array<word, WORDS_C> c = c_words();
   bigint_mul(res.data(), res.size(), x.data(), x.size(), x.size(), c.data(), c.size(), c.size(), ws.data(), ws.size());

   return res;
}

/**
 * @brief Add two numbers. Requires that the result is smaller than 2^448.
 */
std::array<word, Scalar448::WORDS> add(std::span<const word, Scalar448::WORDS> x,
                                       std::span<const word, Scalar448::WORDS> y) {
   std::array<word, Scalar448::WORDS> res;
   copy_mem(res, x);
   const word carry = bigint_add2_nc(res.data(), res.size(), y.data(), y.size());
   BOTAN_ASSERT(carry == 0, "Result fits in output");
   return res;
}

/**
 * @brief x = (x >= L) ? x - L : x. Constant time.
 *
 * @return true iff a reduction was performed
 */
bool ct_subtract_L_if_bigger(std::span<word, Scalar448::WORDS> x) {
   std::array<word, Scalar448::WORDS> tmp;
   copy_mem(tmp, x);
   constexpr auto big_l = big_l_words();

   const word borrow = bigint_sub2(tmp.data(), tmp.size(), big_l.data(), big_l.size());
   const auto smaller_than_L = CT::Mask<word>::expand(borrow);
   smaller_than_L.select_n(x.data(), x.data(), tmp.data(), Scalar448::WORDS);

   return !smaller_than_L.as_bool();
}

template <size_t S>
std::array<word, words_for_bits(S * 8)> bytes_to_words(std::span<const uint8_t, S> x) {
   constexpr size_t words = words_for_bits(S * 8);
   std::array<uint8_t, words * sizeof(word)> x_word_bytes = {0};
   copy_mem(std::span(x_word_bytes).template first<S>(), x);
   return load_le<std::array<word, words>>(x_word_bytes);
}

/**
 * @brief Reduce a 114 byte number (little endian) modulo L.
 *
 * L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
 * as defined in RFC 8032 5.2. The reduction is performed using the algorithm
 * described in the "Handbook of Applied Cryptography" Algorithm 14.47. for
 * m = b^t - c, with b^7 = 2^446 and c = 1381...85
 */
std::array<word, Scalar448::WORDS> ct_reduce_mod_L(const std::array<word, WORDS_REDUCE_SZ> x) {
   const auto [q_0, r_0] = div_mod_2_446(std::span(x));

   auto r = r_0;
   // Three iterations are required. This is tested using the biggest possible input.
   // i = 0:
   const auto q_0_c = mul_c(std::span(q_0));
   const auto [q_1, r_1] = div_mod_2_446(std::span(q_0_c));
   r = add(r, r_1);

   // i = 1
   const auto q_1_c = mul_c(std::span(q_1));
   const auto [q_2, r_2] = div_mod_2_446(std::span(q_1_c));
   r = add(r, r_2);

   // i = 2
   const auto q_2_c = mul_c(std::span(q_2));
   const auto [q_3, r_3] = div_mod_2_446(std::span(q_2_c));
   r = add(r, r_3);

   BOTAN_ASSERT_NOMSG(CT::all_zeros(q_3.data(), q_3.size()).as_bool());

   // Note that r is maximal 4*(2^446 - 1) < 2^448. Therefore, the addition did not overflow.
   // Also, this means that subtracting L 4 times (at most) will bring r into the range [0, L), since
   // 4*(2^446 - 1) - 4*(2^446 - c) = 4*(c - 1) < L.
   for(size_t i = 0; i < 4; ++i) {
      ct_subtract_L_if_bigger(r);
   }

   return r;
}

}  // namespace

Scalar448::Scalar448(std::span<const uint8_t> in_bytes) {
   BOTAN_ARG_CHECK(in_bytes.size() <= 114, "Input must be at most 114 bytes long");
   std::array<uint8_t, 114> max_bytes = {0};
   copy_mem(std::span(max_bytes).first(in_bytes.size()), in_bytes);

   const auto x_words = bytes_to_words(std::span<const uint8_t, 114>(max_bytes));
   m_scalar_words = ct_reduce_mod_L(x_words);
}

bool Scalar448::get_bit(size_t bit_pos) const {
   BOTAN_ARG_CHECK(bit_pos < 446, "Bit position out of range");
   constexpr size_t word_sz = sizeof(word) * 8;
   return (m_scalar_words[bit_pos / word_sz] >> (bit_pos % word_sz)) & 1;
}

Scalar448 Scalar448::operator+(const Scalar448& other) const {
   auto sum = add(m_scalar_words, other.m_scalar_words);
   ct_subtract_L_if_bigger(sum);
   return Scalar448(sum);
}

Scalar448 Scalar448::operator*(const Scalar448& other) const {
   std::array<word, WORDS_REDUCE_SZ> product = {0};
   std::array<word, WORDS_REDUCE_SZ> ws = {0};
   bigint_mul(product.data(),
              product.size(),
              m_scalar_words.data(),
              m_scalar_words.size(),
              m_scalar_words.size(),
              other.m_scalar_words.data(),
              other.m_scalar_words.size(),
              other.m_scalar_words.size(),
              ws.data(),
              ws.size());

   return Scalar448(ct_reduce_mod_L(product));
}

bool Scalar448::bytes_are_reduced(std::span<const uint8_t> x) {
   BOTAN_ARG_CHECK(x.size() >= BYTES, "Input is not long enough (at least 446 bits)");
   // remember: `x` contains a big int in little-endian
   const auto leading_zeros = x.subspan(BYTES);
   const auto leading_zeros_are_zero = CT::all_zeros(leading_zeros.data(), leading_zeros.size());
   auto x_sig_words = bytes_to_words(x.first<56>());
   const auto least_56_bytes_smaller_L = CT::Mask<uint8_t>::expand(!ct_subtract_L_if_bigger(x_sig_words));
   return (leading_zeros_are_zero & least_56_bytes_smaller_L).as_bool();
}

}  // namespace Botan

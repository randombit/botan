/*
* Ed25519 scalar
* (C) 2017 Ribose Inc
*     2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ed25519_scalar.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mp_core.h>

namespace Botan {

/*
* Multiplications use Montgomery reduction with R = 2^256; the required
* power of R is folded into one of the multiplicands via the precomputed
* R and R^2 mod l.
*/
namespace {

constexpr size_t SC_WORDS = 256 / WordInfo<word>::bits;

consteval std::array<word, SC_WORDS> sc_l_words() {
   const std::array<uint8_t, 32> l_bytes{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                         0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
   return load_le<std::array<word, SC_WORDS>>(l_bytes);
}

constexpr std::array<word, SC_WORDS> SC_L = sc_l_words();

/*
* -l^-1 mod 2^W (the Montgomery p_dash value)
*/
consteval word sc_l_dash() {
   // Each Newton iteration doubles the number of correct low bits
   word y = 1;
   for(size_t i = 0; i != 6; ++i) {
      y = static_cast<word>(y * (static_cast<word>(2) - SC_L[0] * y));
   }
   return static_cast<word>(0) - y;
}

constexpr word SC_L_DASH = sc_l_dash();

/*
* Return 2^k mod l, computed by repeated doubling
*/
consteval std::array<word, SC_WORDS> sc_2_pow_mod_l(size_t k) {
   std::array<word, SC_WORDS> r{};
   r[0] = 1;
   for(size_t i = 0; i != k; ++i) {
      word carry = 0;
      for(size_t j = 0; j != SC_WORDS; ++j) {
         const word w = r[j];
         r[j] = static_cast<word>(w << 1) | carry;
         carry = w >> (WordInfo<word>::bits - 1);
      }

      std::array<word, SC_WORDS> t{};
      word borrow = 0;
      for(size_t j = 0; j != SC_WORDS; ++j) {
         t[j] = word_sub(r[j], SC_L[j], &borrow);
      }
      if(borrow == 0) {
         r = t;
      }
   }
   return r;
}

constexpr std::array<word, SC_WORDS> SC_R1 = sc_2_pow_mod_l(256);
constexpr std::array<word, SC_WORDS> SC_R2 = sc_2_pow_mod_l(512);

/*
* Montgomery multiplication; requires x * y < l * 2^256 (which holds
* whenever either operand is below l), returns x * y * 2^-256 mod l
*/
std::array<word, SC_WORDS> sc_mont_mul(const std::array<word, SC_WORDS>& x, const std::array<word, SC_WORDS>& y) {
   std::array<word, 2 * SC_WORDS> z;  // NOLINT(*-member-init)
   comba_mul<SC_WORDS>(z.data(), x.data(), y.data());

   std::array<word, SC_WORDS> r;   // NOLINT(*-member-init)
   std::array<word, SC_WORDS> ws;  // NOLINT(*-member-init)
   bigint_monty_redc(r.data(), z.data(), SC_L.data(), SC_WORDS, SC_L_DASH, ws.data(), ws.size());
   return r;
}

/*
* Given x, y < l return x + y mod l
*/
std::array<word, SC_WORDS> sc_add(const std::array<word, SC_WORDS>& x, const std::array<word, SC_WORDS>& y) {
   // Since both inputs are below l < 2^253 the sum cannot carry out
   std::array<word, SC_WORDS> r;  // NOLINT(*-member-init)
   word carry = 0;
   for(size_t i = 0; i != SC_WORDS; ++i) {
      r[i] = word_add(x[i], y[i], &carry);
   }

   std::array<word, SC_WORDS> t;  // NOLINT(*-member-init)
   word borrow = 0;
   for(size_t i = 0; i != SC_WORDS; ++i) {
      t[i] = word_sub(r[i], SC_L[i], &borrow);
   }
   CT::conditional_assign_mem(static_cast<word>(1) - borrow, r.data(), t.data(), SC_WORDS);
   return r;
}

std::array<word, SC_WORDS> sc_load(std::span<const uint8_t, 32> b) {
   std::array<word, SC_WORDS> r;  // NOLINT(*-member-init)
   for(size_t i = 0; i != SC_WORDS; ++i) {
      r[i] = load_le<word>(b.data(), i);
   }
   return r;
}

}  // namespace

Ed25519_Scalar Ed25519_Scalar::from_bytes(std::span<const uint8_t, BYTES> b) {
   // x mod l == mont_mul(x, R)
   return Ed25519_Scalar(sc_mont_mul(sc_load(b), SC_R1));
}

Ed25519_Scalar Ed25519_Scalar::from_wide_bytes(std::span<const uint8_t, 2 * BYTES> b) {
   const auto lo = sc_load(b.first<BYTES>());
   const auto hi = sc_load(b.last<BYTES>());

   // (hi * 2^256 + lo) == mont_mul(hi, R^2) + mont_mul(lo, R) (mod l)
   return Ed25519_Scalar(sc_add(sc_mont_mul(hi, SC_R2), sc_mont_mul(lo, SC_R1)));
}

std::optional<Ed25519_Scalar> Ed25519_Scalar::from_canonical_bytes(std::span<const uint8_t, BYTES> b) {
   const auto w = sc_load(b);

   std::array<word, WORDS> t;  // NOLINT(*-member-init)
   word borrow = 0;
   for(size_t i = 0; i != WORDS; ++i) {
      t[i] = word_sub(w[i], SC_L[i], &borrow);
   }

   // If subtracting l did not borrow then the value was not reduced
   if(borrow == 0) {
      return std::nullopt;
   }
   return Ed25519_Scalar(w);
}

void Ed25519_Scalar::serialize_to(std::span<uint8_t, BYTES> b) const {
   for(size_t i = 0; i != WORDS; ++i) {
      store_le(m_val[i], b.data() + sizeof(word) * i);
   }
}

Ed25519_Scalar Ed25519_Scalar::operator+(const Ed25519_Scalar& other) const {
   return Ed25519_Scalar(sc_add(m_val, other.m_val));
}

Ed25519_Scalar Ed25519_Scalar::operator-() const {
   // Compute l - x, then use zero instead if x was zero
   std::array<word, WORDS> t;  // NOLINT(*-member-init)
   word borrow = 0;
   for(size_t i = 0; i != WORDS; ++i) {
      t[i] = word_sub(SC_L[i], m_val[i], &borrow);
   }

   const std::array<word, WORDS> zeros{};
   const auto x_is_zero = CT::all_zeros(m_val.data(), WORDS).value();
   CT::conditional_assign_mem(x_is_zero, t.data(), zeros.data(), WORDS);
   return Ed25519_Scalar(t);
}

Ed25519_Scalar Ed25519_Scalar::operator*(const Ed25519_Scalar& other) const {
   // (a*b) == mont_mul(mont_mul(a, R^2), b) (mod l)
   return Ed25519_Scalar(sc_mont_mul(sc_mont_mul(m_val, SC_R2), other.m_val));
}

}  // namespace Botan

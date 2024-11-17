/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bls12_381.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>

namespace Botan::BLS12_381 {

namespace {

constexpr auto SCALAR_P = hex_to_words<word>("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

// R1 = 2**256 % p
constexpr auto SCALAR_R1 = hex_to_words<word>("1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");

// R2 = (R1**2) % p
constexpr auto SCALAR_R2 = hex_to_words<word>("748d9d99f59ff1105d314967254398f2b6cedcb87925c23c999e990f3f29c6d");

// R3 = (R1*R2) % p
constexpr auto SCALAR_R3 = hex_to_words<word>("6e2a5bb9c8db33e973d13c71c7b5f4181b3e0d188cf06990c62c1807439b73af");

constexpr word SCALAR_P_DASH = monty_inverse(SCALAR_P[0]);

std::array<word, Scalar::N> scalar_redc(std::array<word, 2 * Scalar::N> v) {
   std::array<word, Scalar::N> ws;
   // TODO clean this up to avoid the copy
   bigint_monty_redc(v.data(), SCALAR_P.data(), SCALAR_P.size(), SCALAR_P_DASH, ws.data(), ws.size());
   copy_mem(ws.data(), v.data(), ws.size());
   return ws;
}

std::array<word, Scalar::N> scalar_to_rep(std::array<word, Scalar::N> v) {
   std::array<word, 2 * Scalar::N> z;
   comba_mul<Scalar::N>(z.data(), v.data(), SCALAR_R2.data());
   return scalar_redc(z);
}

std::array<word, Scalar::N> scalar_wide_to_rep(const std::array<word, 2 * Scalar::N>& v) {
   auto redc_v = scalar_redc(v);
   std::array<word, 2 * Scalar::N> z;
   comba_mul<Scalar::N>(z.data(), redc_v.data(), SCALAR_R3.data());
   return scalar_redc(z);
}

std::array<word, Scalar::N> scalar_from_rep(const std::array<word, Scalar::N>& v) {
   std::array<word, 2 * Scalar::N> z{};
   copy_mem(z.data(), v.data(), v.size());
   return scalar_redc(z);
}

}  // namespace

//static
Scalar Scalar::from_words(std::array<word, Scalar::N> v) {
   return Scalar(scalar_to_rep(v));
}

//static
Scalar Scalar::from_u32(uint32_t v) {
   std::array<word, Scalar::N> w{};
   w[0] = v;
   return Scalar::from_words(w);
}

//static
Scalar Scalar::one() {
   return Scalar(SCALAR_R1);
}

std::optional<Scalar> Scalar::deserialize(std::span<const uint8_t> bytes) {
   if(bytes.size() != Scalar::BYTES) {
      return {};
   }

   const auto words = bytes_to_words<word, N, BYTES>(bytes.first<Scalar::BYTES>());

   if(!bigint_ct_is_lt(words.data(), N, SCALAR_P.data(), N).as_bool()) {
      return {};
   }

   return Scalar::from_words(words);
}

Scalar Scalar::from_bytes_wide(std::span<const uint8_t, 64> bytes) {
   return Scalar(scalar_wide_to_rep(bytes_to_words<word, 2 * N, 2 * BYTES>(bytes)));
}

void Scalar::serialize_to(std::span<uint8_t, Scalar::BYTES> bytes) const {
   auto v = scalar_from_rep(m_val);
   std::reverse(v.begin(), v.end());
   store_be(bytes, v);
}

Scalar Scalar::add(const Scalar& other) const {
   std::array<word, Scalar::N> t;
   word carry = bigint_add<word, Scalar::N>(t, value(), other.value());

   std::array<word, Scalar::N> r;
   bigint_monty_maybe_sub<Scalar::N>(r.data(), carry, t.data(), SCALAR_P.data());
   return Scalar(r);
}

Scalar Scalar::sub(const Scalar& other) const {
   return this->add(other.negate());
}

Scalar Scalar::mul(const Scalar& other) const {
   std::array<word, 2 * Scalar::N> z;
   comba_mul<Scalar::N>(z.data(), data(), other.data());
   return Scalar(scalar_redc(z));
}

Scalar Scalar::square() const {
   std::array<word, 2 * Scalar::N> z;
   comba_sqr<Scalar::N>(z.data(), data());
   return Scalar(scalar_redc(z));
}

void Scalar::square_n(size_t n) {
   std::array<word, 2 * N> z;
   for(size_t i = 0; i != n; ++i) {
      comba_sqr<N>(z.data(), this->data());
      m_val = scalar_redc(z);
   }
}

Scalar Scalar::negate() const {
   auto v_is_zero = CT::all_zeros(this->data(), N);

   std::array<word, N> r;
   bigint_sub3(r.data(), SCALAR_P.data(), N, this->data(), N);
   v_is_zero.if_set_zero_out(r.data(), N);
   return Scalar(r);
}

Scalar Scalar::invert() const {
   // Addition chain for exponentiation to p - 2
   // Found using https://github.com/mmcloughlin/addchain
   auto t3 = this->square();
   auto z = t3 * (*this);
   auto t14 = (*this) * z;
   auto t2 = t14 * t3;
   auto t4 = t2.square();
   auto t8 = t2 * t4;
   auto t5 = t8 * (*this);
   auto t11 = t5 * z;
   auto t0 = t11 * t3;
   auto t9 = t0 * t3;
   auto t1 = t11 * t4;
   auto t10 = t1 * t5;
   auto t6 = t10 * t2;
   t2 = t10 * t11;
   auto t7 = t2 * t3;
   t5 = t6 * t9;
   t8 *= t5;
   t3 *= t8;
   t9 *= t3;
   auto t12 = t11 * t9;
   auto t13 = t12 * t14;
   t1 *= t13;
   t11 = t0 * t1;
   t14 *= t11;
   auto t15 = t14 * t4;
   t4 = t0 * t11;
   t0 *= t15;
   t15.square_n(8);
   t14 *= t15;
   t14.square_n(9);
   t13 *= t14;
   t13.square_n(9);
   t13 *= t12;
   t13.square_n(9);
   t12 *= t13;
   t12.square_n(8);
   t11 *= t12;
   t11.square_n(6);
   t10 *= t11;
   t10.square_n(10);
   t9 *= t10;
   t9.square_n(9);
   t8 *= t9;
   t8.square_n(8);
   t8 *= t6;
   t8.square_n(8);
   t8 *= (*this);
   t8.square_n(14);
   t7 *= t8;
   t7.square_n(10);
   t6 *= t7;
   t6.square_n(15);
   t5 *= t6;
   t5.square_n(10);
   t4 *= t5;
   t4.square_n(8);
   t3 *= t4;
   t3.square_n(16);
   t3 *= t1;
   t3.square_n(8);
   t3 *= t0;
   t3.square_n(7);
   t2 *= t3;
   t2.square_n(9);
   t2 *= t0;
   t2.square_n(8);
   t2 *= t1;
   t2.square_n(8);
   t2 *= t0;
   t2.square_n(8);
   t2 *= t0;
   t2.square_n(8);
   t2 *= t0;
   t2.square_n(8);
   t1 *= t2;
   t1.square_n(8);
   t1 *= t0;
   t1.square_n(8);
   t1 *= t0;
   t1.square_n(8);
   t0 *= t1;
   t0.square_n(2);
   z *= t0;
   return z;
}

}  // namespace Botan::BLS12_381

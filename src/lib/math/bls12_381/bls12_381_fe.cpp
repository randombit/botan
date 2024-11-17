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

constexpr auto FE_P = hex_to_words<word>(
   "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");

// R1 = 2**384 % p
constexpr auto FE_R1 = hex_to_words<word>(
   "15f65ec3fa80e4935c071a97a256ec6d77ce5853705257455f48985753c758baebf4000bc40c0002760900000002fffd");

// R2 = (R1**2) % p
constexpr auto FE_R2 = hex_to_words<word>(
   "11988fe592cae3aa9a793e85b519952d67eb88a9939d83c08de5476c4c95b6d50a76e6a609d104f1f4df1f341c341746");

// R3 = (R1*R2) % p
constexpr auto FE_R3 = hex_to_words<word>(
   "aa6346091755d4d2512d4356572472834c04e5e921e17619a53352a615e29dd315f831e03a7adf8ed48ac6bd94ca1e0");

constexpr word FE_P_DASH = monty_inverse(FE_P[0]);

std::array<word, FieldElement::N> fe_redc(std::array<word, 2 * FieldElement::N> v) {
   std::array<word, FieldElement::N> ws;
   // TODO clean this up to avoid the copy
   bigint_monty_redc(v.data(), FE_P.data(), FE_P.size(), FE_P_DASH, ws.data(), ws.size());
   copy_mem(ws.data(), v.data(), ws.size());
   return ws;
}

std::array<word, FieldElement::N> fe_to_rep(std::array<word, FieldElement::N> v) {
   std::array<word, 2 * FieldElement::N> z;
   comba_mul<FieldElement::N>(z.data(), v.data(), FE_R2.data());
   return fe_redc(z);
}

std::array<word, FieldElement::N> fe_wide_to_rep(const std::array<word, 2 * FieldElement::N>& v) {
   auto redc_v = fe_redc(v);
   std::array<word, 2 * FieldElement::N> z;
   comba_mul<FieldElement::N>(z.data(), redc_v.data(), FE_R3.data());
   return fe_redc(z);
}

std::array<word, FieldElement::N> fe_from_rep(const std::array<word, FieldElement::N>& v) {
   std::array<word, 2 * FieldElement::N> z{};
   copy_mem(z.data(), v.data(), v.size());
   return fe_redc(z);
}

}  // namespace

//static
FieldElement FieldElement::from_words(std::array<word, FieldElement::N> v) {
   return FieldElement(fe_to_rep(v));
}

//static
FieldElement FieldElement::from_u32(uint32_t v) {
   std::array<word, FieldElement::N> w{};
   w[0] = v;
   return FieldElement::from_words(w);
}

//static
FieldElement FieldElement::one() {
   return FieldElement(FE_R1);
}

std::optional<FieldElement> FieldElement::deserialize(std::span<const uint8_t> bytes) {
   if(bytes.size() != FieldElement::BYTES) {
      return {};
   }

   const auto words = bytes_to_words<word, N, BYTES>(bytes.first<FieldElement::BYTES>());

   if(!bigint_ct_is_lt(words.data(), N, FE_P.data(), N).as_bool()) {
      return {};
   }

   return FieldElement::from_words(words);
}

FieldElement FieldElement::from_bytes_wide(std::span<const uint8_t, 96> bytes) {
   return FieldElement(fe_wide_to_rep(bytes_to_words<word, 2 * N, 2 * BYTES>(bytes)));
}

void FieldElement::serialize_to(std::span<uint8_t, FieldElement::BYTES> bytes) const {
   auto v = fe_from_rep(m_val);
   std::reverse(v.begin(), v.end());
   store_be(bytes, v);
}

FieldElement FieldElement::add(const FieldElement& other) const {
   std::array<word, FieldElement::N> t;
   word carry = bigint_add<word, FieldElement::N>(t, value(), other.value());

   std::array<word, FieldElement::N> r;
   bigint_monty_maybe_sub<FieldElement::N>(r.data(), carry, t.data(), FE_P.data());
   return FieldElement(r);
}

FieldElement FieldElement::sub(const FieldElement& other) const {
   return this->add(other.negate());
}

FieldElement FieldElement::mul(const FieldElement& other) const {
   std::array<word, 2 * FieldElement::N> z;
   comba_mul<FieldElement::N>(z.data(), data(), other.data());
   return FieldElement(fe_redc(z));
}

FieldElement FieldElement::square() const {
   std::array<word, 2 * FieldElement::N> z;
   comba_sqr<FieldElement::N>(z.data(), data());
   return FieldElement(fe_redc(z));
}

void FieldElement::square_n(size_t n) {
   std::array<word, 2 * N> z;
   for(size_t i = 0; i != n; ++i) {
      comba_sqr<N>(z.data(), this->data());
      m_val = fe_redc(z);
   }
}

FieldElement FieldElement::negate() const {
   auto v_is_zero = CT::all_zeros(this->data(), N);

   std::array<word, N> r;
   bigint_sub3(r.data(), FE_P.data(), N, this->data(), N);
   v_is_zero.if_set_zero_out(r.data(), N);
   return FieldElement(r);
}

FieldElement FieldElement::invert() const {
   // Addition chain for exponentiation to p - 2
   // Found using https://github.com/mmcloughlin/addchain
   auto z = (*this).square();
   auto t3 = z.square();
   auto t10 = t3.square();
   auto t6 = t10 * (*this);
   auto t8 = t6 * z;
   auto t5 = t8 * z;
   auto t24 = t3 * t5;
   auto t1 = t6 * t8;
   auto t17 = t10 * t24;
   auto t9 = t17 * (*this);
   auto t12 = t9.square();
   auto t4 = t12 * z;
   auto t2 = t4 * (*this);
   auto t22 = t12 * t17;
   auto t14 = t22 * z;
   auto t0 = t10 * t22;
   auto t20 = t0 * t10;
   auto t11 = t22 * t9;
   auto t19 = t11 * z;
   auto t16 = t20 * t9;
   auto t7 = t16 * t3;
   t12 *= t0;
   t9 *= t7;
   auto t15 = t9 * z;
   z = t1 * t9;
   auto t21 = t10 * z;
   t4 *= t12;
   t10 = t3 * t4;
   t5 *= t10;
   auto t18 = t1 * t10;
   auto t13 = t24 * t5;
   auto t23 = t13 * t3;
   t3 = t1 * t18;
   t5 = t1 * t13;
   t1 *= t3;
   auto t25 = t13 * t4;
   t25.square_n(8);
   t24 *= t25;
   t24.square_n(11);
   t24 *= t5;
   t24.square_n(11);
   t23 *= t24;
   t23.square_n(8);
   t23 *= t1;
   t23.square_n(7);
   t22 *= t23;
   t22.square_n(9);
   t22 *= t19;
   t22.square_n(10);
   t21 *= t22;
   t21.square_n(7);
   t20 *= t21;
   t20.square_n(9);
   t20 *= t7;
   t20.square_n(6);
   t20 *= t17;
   t20.square_n(11);
   t19 *= t20;
   t19.square_n(9);
   t19 *= t3;
   t19.square_n(10);
   t18 *= t19;
   t18.square_n(6);
   t17 *= t18;
   t17.square_n(10);
   t16 *= t17;
   t16.square_n(9);
   t15 *= t16;
   t15.square_n(11);
   t14 *= t15;
   t14.square_n(10);
   t13 *= t14;
   t13.square_n(9);
   t12 *= t13;
   t12.square_n(9);
   t12 *= t4;
   t12.square_n(8);
   t11 *= t12;
   t11.square_n(10);
   t10 *= t11;
   t10.square_n(9);
   t9 *= t10;
   t9.square_n(12);
   t9 *= t7;
   t9.square_n(5);
   t8 *= t9;
   t8.square_n(11);
   t7 *= t8;
   t7.square_n(7);
   t6 *= t7;
   t6.square_n(13);
   t5 *= t6;
   t5.square_n(9);
   t4 *= t5;
   t4.square_n(8);
   t4 *= t1;
   t4.square_n(8);
   t3 *= t4;
   t3.square_n(11);
   t3 *= z;
   t3.square_n(8);
   t3 *= t1;
   t3.square_n(8);
   t3 *= t1;
   t3.square_n(6);
   t2 *= t3;
   t2.square_n(10);
   t2 *= t1;
   t2.square_n(9);
   t2 *= t1;
   t2.square_n(8);
   t2 *= t1;
   t2.square_n(8);
   t2 *= t1;
   t2.square_n(8);
   t1 *= t2;
   t1.square_n(7);
   t0 *= t1;
   t0.square_n(9);
   z *= t0;
   return z;
}

}  // namespace Botan::BLS12_381

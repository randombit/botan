/*
* (C) 2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/monty.h>

#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/internal/mp_core.h>

#include <utility>

namespace Botan {

Montgomery_Params::Montgomery_Params(const BigInt& p, const Modular_Reducer& mod_p) {
   if(p.is_even() || p < 3) {
      throw Invalid_Argument("Montgomery_Params invalid modulus");
   }

   m_p = p;
   m_p_words = m_p.sig_words();
   m_p_dash = monty_inverse(m_p.word_at(0));

   const BigInt r = BigInt::power_of_2(m_p_words * WordInfo<word>::bits);

   m_r1 = mod_p.reduce(r);
   m_r2 = mod_p.square(m_r1);
   m_r3 = mod_p.multiply(m_r1, m_r2);
}

Montgomery_Params::Montgomery_Params(const BigInt& p) {
   if(p.is_even() || p < 3) {
      throw Invalid_Argument("Montgomery_Params invalid modulus");
   }

   m_p = p;
   m_p_words = m_p.sig_words();
   m_p_dash = monty_inverse(m_p.word_at(0));

   const BigInt r = BigInt::power_of_2(m_p_words * WordInfo<word>::bits);

   auto mod_p = Modular_Reducer::for_secret_modulus(p);

   m_r1 = mod_p.reduce(r);
   m_r2 = mod_p.square(m_r1);
   m_r3 = mod_p.multiply(m_r1, m_r2);
}

BigInt Montgomery_Params::redc(const BigInt& x, secure_vector<word>& ws) const {
   const size_t output_size = m_p_words + 1;

   if(ws.size() < output_size) {
      ws.resize(output_size);
   }

   BigInt z = x;
   z.grow_to(2 * m_p_words);

   bigint_monty_redc(z.mutable_data(), m_p._data(), m_p_words, m_p_dash, ws.data(), ws.size());

   return z;
}

void Montgomery_Params::redc_in_place(BigInt& x, secure_vector<word>& ws) const {
   const size_t output_size = 2 * m_p_words;

   if(ws.size() < output_size) {
      ws.resize(output_size);
   }

   x.grow_to(output_size);

   bigint_monty_redc(x.mutable_data(), m_p._data(), m_p_words, m_p_dash, ws.data(), ws.size());
}

BigInt Montgomery_Params::mul(const BigInt& x, const BigInt& y, secure_vector<word>& ws) const {
   BigInt z = BigInt::with_capacity(2 * m_p_words);
   this->mul(z, x, y, ws);
   return z;
}

void Montgomery_Params::mul(BigInt& z, const BigInt& x, const BigInt& y, secure_vector<word>& ws) const {
   const size_t output_size = 2 * m_p_words;

   if(ws.size() < output_size) {
      ws.resize(output_size);
   }

   BOTAN_DEBUG_ASSERT(x.sig_words() <= m_p_words);
   BOTAN_DEBUG_ASSERT(y.sig_words() <= m_p_words);

   if(z.size() < output_size) {
      z.grow_to(output_size);
   }

   bigint_mul(z.mutable_data(),
              z.size(),
              x._data(),
              x.size(),
              std::min(m_p_words, x.size()),
              y._data(),
              y.size(),
              std::min(m_p_words, y.size()),
              ws.data(),
              ws.size());

   bigint_monty_redc(z.mutable_data(), m_p._data(), m_p_words, m_p_dash, ws.data(), ws.size());
}

BigInt Montgomery_Params::mul(const BigInt& x, std::span<const word> y, secure_vector<word>& ws) const {
   BigInt z = BigInt::with_capacity(2 * m_p_words);
   this->mul(z, x, y, ws);
   return z;
}

void Montgomery_Params::mul(BigInt& z, const BigInt& x, std::span<const word> y, secure_vector<word>& ws) const {
   const size_t output_size = 2 * m_p_words;
   if(ws.size() < output_size) {
      ws.resize(output_size);
   }
   if(z.size() < output_size) {
      z.grow_to(output_size);
   }

   BOTAN_DEBUG_ASSERT(x.sig_words() <= m_p_words);

   bigint_mul(z.mutable_data(),
              z.size(),
              x._data(),
              x.size(),
              std::min(m_p_words, x.size()),
              y.data(),
              y.size(),
              std::min(m_p_words, y.size()),
              ws.data(),
              ws.size());

   bigint_monty_redc(z.mutable_data(), m_p._data(), m_p_words, m_p_dash, ws.data(), ws.size());
}

void Montgomery_Params::mul_by(BigInt& x, std::span<const word> y, secure_vector<word>& ws) const {
   const size_t output_size = 2 * m_p_words;

   if(ws.size() < 2 * output_size) {
      ws.resize(2 * output_size);
   }

   word* z_data = &ws[0];
   word* ws_data = &ws[output_size];

   BOTAN_DEBUG_ASSERT(x.sig_words() <= m_p_words);

   bigint_mul(z_data,
              output_size,
              x._data(),
              x.size(),
              std::min(m_p_words, x.size()),
              y.data(),
              y.size(),
              std::min(m_p_words, y.size()),
              ws_data,
              output_size);

   bigint_monty_redc(z_data, m_p._data(), m_p_words, m_p_dash, ws_data, output_size);

   if(x.size() < output_size) {
      x.grow_to(output_size);
   }
   copy_mem(x.mutable_data(), z_data, output_size);
}

void Montgomery_Params::mul_by(BigInt& x, const BigInt& y, secure_vector<word>& ws) const {
   const size_t output_size = 2 * m_p_words;

   if(ws.size() < 2 * output_size) {
      ws.resize(2 * output_size);
   }

   word* z_data = &ws[0];
   word* ws_data = &ws[output_size];

   BOTAN_DEBUG_ASSERT(x.sig_words() <= m_p_words);

   bigint_mul(z_data,
              output_size,
              x._data(),
              x.size(),
              std::min(m_p_words, x.size()),
              y._data(),
              y.size(),
              std::min(m_p_words, y.size()),
              ws_data,
              output_size);

   bigint_monty_redc(z_data, m_p._data(), m_p_words, m_p_dash, ws_data, output_size);

   if(x.size() < output_size) {
      x.grow_to(output_size);
   }
   copy_mem(x.mutable_data(), z_data, output_size);
}

BigInt Montgomery_Params::sqr(const BigInt& x, secure_vector<word>& ws) const {
   BOTAN_DEBUG_ASSERT(x.sig_words() <= m_p_words);
   return this->sqr(std::span{x._data(), x.size()}, ws);
}

BigInt Montgomery_Params::sqr(std::span<const word> x, secure_vector<word>& ws) const {
   BigInt z = BigInt::with_capacity(2 * m_p_words);
   this->sqr(z, x, ws);
   return z;
}

void Montgomery_Params::sqr(BigInt& z, const BigInt& x, secure_vector<word>& ws) const {
   this->sqr(z, std::span{x._data(), x.size()}, ws);
}

void Montgomery_Params::sqr(BigInt& z, std::span<const word> x, secure_vector<word>& ws) const {
   const size_t output_size = 2 * m_p_words;

   if(ws.size() < output_size) {
      ws.resize(output_size);
   }

   if(z.size() < output_size) {
      z.grow_to(output_size);
   }

   bigint_sqr(z.mutable_data(), z.size(), x.data(), x.size(), std::min(m_p_words, x.size()), ws.data(), ws.size());

   bigint_monty_redc(z.mutable_data(), m_p._data(), m_p_words, m_p_dash, ws.data(), ws.size());
}

void Montgomery_Params::square_this(BigInt& x, secure_vector<word>& ws) const {
   const size_t output_size = 2 * m_p_words;

   if(ws.size() < 2 * output_size) {
      ws.resize(2 * output_size);
   }

   word* z_data = &ws[0];
   word* ws_data = &ws[output_size];

   BOTAN_DEBUG_ASSERT(x.sig_words() <= m_p_words);

   bigint_sqr(z_data, output_size, x._data(), x.size(), std::min(m_p_words, x.size()), ws_data, output_size);

   bigint_monty_redc(z_data, m_p._data(), m_p_words, m_p_dash, ws_data, output_size);

   if(x.size() < output_size) {
      x.grow_to(output_size);
   }
   copy_mem(x.mutable_data(), z_data, output_size);
}

Montgomery_Int Montgomery_Int::one(const std::shared_ptr<const Montgomery_Params>& params) {
   return Montgomery_Int(params, params->R1(), false);
}

Montgomery_Int Montgomery_Int::from_wide_int(const std::shared_ptr<const Montgomery_Params>& params, const BigInt& x) {
   //BOTAN_ARG_CHECK(x < params->p() * params->p(), "Input too large");

   secure_vector<word> ws;
   auto redc_x = params->mul(params->redc(x, ws), params->R3(), ws);
   return Montgomery_Int(params, redc_x, false);
}

Montgomery_Int::Montgomery_Int(const std::shared_ptr<const Montgomery_Params>& params,
                               const BigInt& v,
                               bool redc_needed) :
      m_params(params) {
   if(redc_needed == false) {
      m_v = v;
   } else {
      BOTAN_ASSERT_NOMSG(m_v < m_params->p());
      secure_vector<word> ws;
      m_v = m_params->mul(v, m_params->R2(), ws);
   }
}

Montgomery_Int::Montgomery_Int(const std::shared_ptr<const Montgomery_Params>& params,
                               const uint8_t bits[],
                               size_t len,
                               bool redc_needed) :
      m_params(params), m_v(bits, len) {
   if(redc_needed) {
      BOTAN_ASSERT_NOMSG(m_v < m_params->p());
      secure_vector<word> ws;
      m_v = m_params->mul(m_v, m_params->R2(), ws);
   }
}

Montgomery_Int::Montgomery_Int(std::shared_ptr<const Montgomery_Params> params,
                               const word words[],
                               size_t len,
                               bool redc_needed) :
      m_params(std::move(params)) {
   m_v.set_words(words, len);

   if(redc_needed) {
      BOTAN_ASSERT_NOMSG(m_v < m_params->p());
      secure_vector<word> ws;
      m_v = m_params->mul(m_v, m_params->R2(), ws);
   }
}

void Montgomery_Int::fix_size() {
   const size_t p_words = m_params->p_words();
   BOTAN_DEBUG_ASSERT(m_v.sig_words() <= p_words);
   m_v.grow_to(p_words);
}

bool Montgomery_Int::operator==(const Montgomery_Int& other) const {
   return m_v == other.m_v && m_params->p() == other.m_params->p();
}

std::vector<uint8_t> Montgomery_Int::serialize() const {
   return value().serialize();
}

size_t Montgomery_Int::size() const {
   return m_params->p().bytes();
}

bool Montgomery_Int::is_one() const {
   return m_v == m_params->R1();
}

bool Montgomery_Int::is_zero() const {
   return m_v.is_zero();
}

BigInt Montgomery_Int::value() const {
   secure_vector<word> ws;
   return m_params->redc(m_v, ws);
}

Montgomery_Int Montgomery_Int::operator+(const Montgomery_Int& other) const {
   BOTAN_STATE_CHECK(other.m_params == m_params);
   secure_vector<word> ws;
   BigInt z = m_v;
   z.mod_add(other.m_v, m_params->p(), ws);
   return Montgomery_Int(m_params, z, false);
}

Montgomery_Int Montgomery_Int::operator-(const Montgomery_Int& other) const {
   BOTAN_STATE_CHECK(other.m_params == m_params);
   secure_vector<word> ws;
   BigInt z = m_v;
   z.mod_sub(other.m_v, m_params->p(), ws);
   return Montgomery_Int(m_params, z, false);
}

Montgomery_Int& Montgomery_Int::operator+=(const Montgomery_Int& other) {
   BOTAN_STATE_CHECK(other.m_params == m_params);
   secure_vector<word> ws;
   return this->add(other, ws);
}

Montgomery_Int& Montgomery_Int::add(const Montgomery_Int& other, secure_vector<word>& ws) {
   BOTAN_STATE_CHECK(other.m_params == m_params);
   m_v.mod_add(other.m_v, m_params->p(), ws);
   return (*this);
}

Montgomery_Int& Montgomery_Int::operator-=(const Montgomery_Int& other) {
   BOTAN_STATE_CHECK(other.m_params == m_params);
   secure_vector<word> ws;
   return this->sub(other, ws);
}

Montgomery_Int& Montgomery_Int::sub(const Montgomery_Int& other, secure_vector<word>& ws) {
   BOTAN_STATE_CHECK(other.m_params == m_params);
   m_v.mod_sub(other.m_v, m_params->p(), ws);
   return (*this);
}

Montgomery_Int Montgomery_Int::operator*(const Montgomery_Int& other) const {
   BOTAN_STATE_CHECK(other.m_params == m_params);
   secure_vector<word> ws;
   return Montgomery_Int(m_params, m_params->mul(m_v, other.m_v, ws), false);
}

Montgomery_Int Montgomery_Int::mul(const Montgomery_Int& other, secure_vector<word>& ws) const {
   BOTAN_STATE_CHECK(other.m_params == m_params);
   return Montgomery_Int(m_params, m_params->mul(m_v, other.m_v, ws), false);
}

Montgomery_Int& Montgomery_Int::mul_by(const Montgomery_Int& other, secure_vector<word>& ws) {
   BOTAN_STATE_CHECK(other.m_params == m_params);
   m_params->mul_by(m_v, other.m_v, ws);
   return (*this);
}

Montgomery_Int& Montgomery_Int::mul_by(const secure_vector<word>& other, secure_vector<word>& ws) {
   m_params->mul_by(m_v, other, ws);
   return (*this);
}

Montgomery_Int& Montgomery_Int::operator*=(const Montgomery_Int& other) {
   BOTAN_STATE_CHECK(other.m_params == m_params);
   secure_vector<word> ws;
   return mul_by(other, ws);
}

Montgomery_Int& Montgomery_Int::operator*=(const secure_vector<word>& other) {
   secure_vector<word> ws;
   return mul_by(other, ws);
}

Montgomery_Int& Montgomery_Int::square_this_n_times(secure_vector<word>& ws, size_t n) {
   for(size_t i = 0; i != n; ++i) {
      m_params->square_this(m_v, ws);
   }
   return (*this);
}

Montgomery_Int& Montgomery_Int::square_this(secure_vector<word>& ws) {
   m_params->square_this(m_v, ws);
   return (*this);
}

Montgomery_Int Montgomery_Int::square(secure_vector<word>& ws) const {
   return Montgomery_Int(m_params, m_params->sqr(m_v, ws), false);
}

Montgomery_Int Montgomery_Int::cube(secure_vector<word>& ws) const {
   return Montgomery_Int(m_params, m_params->sqr(m_v, ws), false);
}

Montgomery_Int Montgomery_Int::additive_inverse() const {
   return Montgomery_Int(m_params, m_params->p()) - (*this);
}

Montgomery_Int& Montgomery_Int::mul_by_2(secure_vector<word>& ws) {
   m_v.mod_mul(2, m_params->p(), ws);
   return (*this);
}

Montgomery_Int& Montgomery_Int::mul_by_3(secure_vector<word>& ws) {
   m_v.mod_mul(3, m_params->p(), ws);
   return (*this);
}

Montgomery_Int& Montgomery_Int::mul_by_4(secure_vector<word>& ws) {
   m_v.mod_mul(4, m_params->p(), ws);
   return (*this);
}

Montgomery_Int& Montgomery_Int::mul_by_8(secure_vector<word>& ws) {
   m_v.mod_mul(8, m_params->p(), ws);
   return (*this);
}

}  // namespace Botan

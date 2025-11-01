/*
* (C) 2018,2024,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/monty.h>

#include <botan/internal/barrett.h>
#include <botan/internal/mp_core.h>
#include <array>

namespace Botan {

namespace {

// If the modulus is at most this many words, then use the stack instead
// of a heap variable for some temporary values
constexpr size_t MontgomeryUseStackLimit = 32;

}  // namespace

Montgomery_Params::Data::Data(const BigInt& p, const Barrett_Reduction& mod_p) {
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

   // Barrett should be at least zero prefixing up to modulus size
   BOTAN_ASSERT_NOMSG(m_r1.size() >= m_p_words);
   BOTAN_ASSERT_NOMSG(m_r2.size() >= m_p_words);
   BOTAN_ASSERT_NOMSG(m_r3.size() >= m_p_words);
}

Montgomery_Params::Montgomery_Params(const BigInt& p, const Barrett_Reduction& mod_p) :
      m_data(std::make_shared<Data>(p, mod_p)) {}

Montgomery_Params::Montgomery_Params(const BigInt& p) :
      Montgomery_Params(p, Barrett_Reduction::for_secret_modulus(p)) {}

bool Montgomery_Params::operator==(const Montgomery_Params& other) const {
   if(this->m_data == other.m_data) {
      return true;
   }

   return (this->m_data->p() == other.m_data->p());
}

BigInt Montgomery_Params::redc(const BigInt& x, secure_vector<word>& ws) const {
   const size_t p_size = this->p_words();

   if(ws.size() < p_size) {
      ws.resize(p_size);
   }

   BigInt z = x;
   z.grow_to(2 * p_size);

   bigint_monty_redc_inplace(z.mutable_data(), this->p()._data(), p_size, this->p_dash(), ws.data(), ws.size());

   return z;
}

BigInt Montgomery_Params::mul(const BigInt& x, const BigInt& y, secure_vector<word>& ws) const {
   const size_t p_size = this->p_words();
   BigInt z = BigInt::with_capacity(2 * p_size);
   this->mul(z, x, y, ws);
   return z;
}

void Montgomery_Params::mul(BigInt& z, const BigInt& x, const BigInt& y, secure_vector<word>& ws) const {
   const size_t p_size = this->p_words();

   if(ws.size() < 2 * p_size) {
      ws.resize(2 * p_size);
   }

   BOTAN_DEBUG_ASSERT(x.sig_words() <= p_size);
   BOTAN_DEBUG_ASSERT(y.sig_words() <= p_size);

   if(z.size() < 2 * p_size) {
      z.grow_to(2 * p_size);
   }

   bigint_mul(z.mutable_data(),
              z.size(),
              x._data(),
              x.size(),
              std::min(p_size, x.size()),
              y._data(),
              y.size(),
              std::min(p_size, y.size()),
              ws.data(),
              ws.size());

   bigint_monty_redc_inplace(z.mutable_data(), this->p()._data(), p_size, this->p_dash(), ws.data(), ws.size());
}

void Montgomery_Params::mul(BigInt& z, const BigInt& x, std::span<const word> y, secure_vector<word>& ws) const {
   const size_t p_size = this->p_words();

   if(ws.size() < 2 * p_size) {
      ws.resize(2 * p_size);
   }
   if(z.size() < 2 * p_size) {
      z.grow_to(2 * p_size);
   }

   BOTAN_DEBUG_ASSERT(x.sig_words() <= p_size);

   bigint_mul(z.mutable_data(),
              z.size(),
              x._data(),
              x.size(),
              std::min(p_size, x.size()),
              y.data(),
              y.size(),
              std::min(p_size, y.size()),
              ws.data(),
              ws.size());

   bigint_monty_redc_inplace(z.mutable_data(), this->p()._data(), p_size, this->p_dash(), ws.data(), ws.size());
}

void Montgomery_Params::mul_by(BigInt& x, const BigInt& y, secure_vector<word>& ws) const {
   const size_t p_size = this->p_words();

   if(ws.size() < 4 * p_size) {
      ws.resize(4 * p_size);
   }

   word* z_data = ws.data();
   word* ws_data = &ws[2 * p_size];

   BOTAN_DEBUG_ASSERT(x.sig_words() <= p_size);

   bigint_mul(z_data,
              2 * p_size,
              x._data(),
              x.size(),
              std::min(p_size, x.size()),
              y._data(),
              y.size(),
              std::min(p_size, y.size()),
              ws_data,
              2 * p_size);

   bigint_monty_redc_inplace(z_data, this->p()._data(), p_size, this->p_dash(), ws_data, 2 * p_size);

   if(x.size() < 2 * p_size) {
      x.grow_to(2 * p_size);
   }
   copy_mem(x.mutable_data(), z_data, 2 * p_size);
}

BigInt Montgomery_Params::sqr(const BigInt& x, secure_vector<word>& ws) const {
   BOTAN_DEBUG_ASSERT(x.sig_words() <= this->p_words());
   return this->sqr(std::span{x._data(), x.size()}, ws);
}

BigInt Montgomery_Params::sqr(std::span<const word> x, secure_vector<word>& ws) const {
   const size_t p_size = this->p_words();
   BigInt z = BigInt::with_capacity(2 * p_size);
   this->sqr(z, x, ws);
   return z;
}

void Montgomery_Params::sqr(BigInt& z, const BigInt& x, secure_vector<word>& ws) const {
   this->sqr(z, std::span{x._data(), x.size()}, ws);
}

void Montgomery_Params::sqr(BigInt& z, std::span<const word> x, secure_vector<word>& ws) const {
   const size_t p_size = this->p_words();

   if(ws.size() < 2 * p_size) {
      ws.resize(2 * p_size);
   }

   if(z.size() < 2 * p_size) {
      z.grow_to(2 * p_size);
   }

   bigint_sqr(z.mutable_data(), z.size(), x.data(), x.size(), std::min(p_size, x.size()), ws.data(), ws.size());

   bigint_monty_redc_inplace(z.mutable_data(), this->p()._data(), p_size, this->p_dash(), ws.data(), ws.size());
}

Montgomery_Int::Montgomery_Int(const Montgomery_Params& params, secure_vector<word> words) :
      m_params(params), m_v(std::move(words)) {
   BOTAN_ASSERT_NOMSG(m_v.size() == m_params.p_words());
}

Montgomery_Int Montgomery_Int::one(const Montgomery_Params& params) {
   return Montgomery_Int(params, params.R1(), false);
}

Montgomery_Int Montgomery_Int::from_wide_int(const Montgomery_Params& params, const BigInt& x) {
   secure_vector<word> ws;
   auto redc_x = params.mul(params.redc(x, ws), params.R3(), ws);
   return Montgomery_Int(params, redc_x, false);
}

Montgomery_Int::Montgomery_Int(const Montgomery_Params& params, const BigInt& v, bool redc_needed) :
      m_params(params), m_v(m_params.p_words()) {
   BOTAN_ASSERT_NOMSG(v < m_params.p());

   const size_t p_size = m_params.p_words();

   auto v_span = v._as_span();

   if(v_span.size() > p_size) {
      // Safe to truncate the span since we already checked v < p
      v_span = v_span.first(p_size);
   }

   BOTAN_ASSERT_NOMSG(m_v.size() >= v_span.size());

   copy_mem(std::span{m_v}.first(v_span.size()), v_span);

   if(redc_needed) {
      secure_vector<word> ws;
      this->mul_by(m_params.R2()._as_span().first(p_size), ws);
   }
}

Montgomery_Int::Montgomery_Int(const Montgomery_Params& params, std::span<const word> words) :
      m_params(params), m_v(words.begin(), words.end()) {
   BOTAN_ARG_CHECK(m_v.size() == m_params.p_words(), "Invalid input span");
}

std::vector<uint8_t> Montgomery_Int::serialize() const {
   return value().serialize();
}

BigInt Montgomery_Int::value() const {
   secure_vector<word> ws(m_params.p_words());

   secure_vector<word> z = m_v;
   z.resize(2 * m_params.p_words());  // zero extend

   bigint_monty_redc_inplace(
      z.data(), m_params.p()._data(), m_params.p_words(), m_params.p_dash(), ws.data(), ws.size());

   return BigInt::_from_words(z);
}

Montgomery_Int Montgomery_Int::operator+(const Montgomery_Int& other) const {
   BOTAN_STATE_CHECK(other.m_params == m_params);

   const size_t p_size = m_params.p_words();
   BOTAN_ASSERT_NOMSG(m_v.size() == p_size && other.m_v.size() == p_size);

   secure_vector<word> z(2 * p_size);

   word* r = std::span{z}.first(p_size).data();
   word* t = std::span{z}.last(p_size).data();

   // t = this + other
   const word carry = bigint_add3(t, m_v.data(), p_size, other.m_v.data(), p_size);

   // Conditionally subtract r = t - p
   bigint_monty_maybe_sub(p_size, r, carry, t, m_params.p()._data());

   z.resize(p_size);  // truncate leaving only r
   return Montgomery_Int(m_params, std::move(z));
}

Montgomery_Int Montgomery_Int::operator-(const Montgomery_Int& other) const {
   BOTAN_STATE_CHECK(other.m_params == m_params);

   const size_t p_size = m_params.p_words();
   BOTAN_ASSERT_NOMSG(m_v.size() == p_size && other.m_v.size() == p_size);

   secure_vector<word> t(p_size);
   const word borrow = bigint_sub3(t.data(), m_v.data(), p_size, other.m_v.data(), p_size);

   bigint_cnd_add(borrow, t.data(), m_params.p()._data(), p_size);

   return Montgomery_Int(m_params, std::move(t));
}

Montgomery_Int Montgomery_Int::mul(const Montgomery_Int& other, secure_vector<word>& ws) const {
   BOTAN_STATE_CHECK(other.m_params == m_params);

   const size_t p_size = m_params.p_words();
   BOTAN_ASSERT_NOMSG(m_v.size() == p_size && other.m_v.size() == p_size);

   if(ws.size() < 2 * p_size) {
      ws.resize(2 * p_size);
   }

   secure_vector<word> z(2 * p_size);

   bigint_mul(z.data(), z.size(), m_v.data(), p_size, p_size, other.m_v.data(), p_size, p_size, ws.data(), ws.size());

   bigint_monty_redc_inplace(z.data(), m_params.p()._data(), p_size, m_params.p_dash(), ws.data(), ws.size());
   z.resize(p_size);  // truncate off high zero words

   return Montgomery_Int(m_params, std::move(z));
}

Montgomery_Int& Montgomery_Int::mul_by(const Montgomery_Int& other, secure_vector<word>& ws) {
   BOTAN_STATE_CHECK(other.m_params == m_params);
   return this->mul_by(std::span{other.m_v}, ws);
}

Montgomery_Int& Montgomery_Int::mul_by(std::span<const word> other, secure_vector<word>& ws) {
   const size_t p_size = m_params.p_words();
   BOTAN_ASSERT_NOMSG(m_v.size() == p_size && other.size() == p_size);

   if(ws.size() < 2 * p_size) {
      ws.resize(2 * p_size);
   }

   auto do_mul_by = [&](std::span<word> z) {
      bigint_mul(z.data(), z.size(), m_v.data(), p_size, p_size, other.data(), p_size, p_size, ws.data(), ws.size());

      bigint_monty_redc_inplace(z.data(), m_params.p()._data(), p_size, m_params.p_dash(), ws.data(), ws.size());

      copy_mem(m_v, z.first(p_size));
   };

   if(p_size <= MontgomeryUseStackLimit) {
      std::array<word, 2 * MontgomeryUseStackLimit> z{};
      do_mul_by(z);
   } else {
      secure_vector<word> z(2 * p_size);
      do_mul_by(z);
   }

   return (*this);
}

Montgomery_Int& Montgomery_Int::square_this_n_times(secure_vector<word>& ws, size_t n) {
   const size_t p_size = m_params.p_words();
   BOTAN_ASSERT_NOMSG(m_v.size() == p_size);

   if(ws.size() < 2 * p_size) {
      ws.resize(2 * p_size);
   }

   auto do_sqr_n = [&](std::span<word> z) {
      for(size_t i = 0; i != n; ++i) {
         bigint_sqr(z.data(), 2 * p_size, m_v.data(), p_size, p_size, ws.data(), ws.size());

         bigint_monty_redc_inplace(z.data(), m_params.p()._data(), p_size, m_params.p_dash(), ws.data(), ws.size());

         copy_mem(m_v, std::span{z}.first(p_size));
      }
   };

   if(p_size <= MontgomeryUseStackLimit) {
      std::array<word, 2 * MontgomeryUseStackLimit> z{};
      do_sqr_n(z);
   } else {
      secure_vector<word> z(2 * p_size);
      do_sqr_n(z);
   }

   return (*this);
}

Montgomery_Int Montgomery_Int::square(secure_vector<word>& ws) const {
   auto z = (*this);
   z.square_this_n_times(ws, 1);
   return z;
}

}  // namespace Botan

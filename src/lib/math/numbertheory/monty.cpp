/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/monty.h>
#include <botan/reducer.h>
#include <botan/internal/mp_core.h>

namespace Botan {

Montgomery_Params::Montgomery_Params(const BigInt& p,
                                     const Modular_Reducer& mod_p)
   {
   if(p.is_negative() || p.is_even())
      throw Invalid_Argument("Montgomery_Params invalid modulus");

   m_p = p;
   m_p_words = m_p.sig_words();
   m_p_dash = monty_inverse(m_p.word_at(0));

   const BigInt r = BigInt::power_of_2(m_p_words * BOTAN_MP_WORD_BITS);

   m_r1 = mod_p.reduce(r);
   m_r2 = mod_p.square(m_r1);
   m_r3 = mod_p.multiply(m_r1, m_r2);
   }

BigInt Montgomery_Params::inv_mod_p(const BigInt& x) const
   {
   return ct_inverse_mod_odd_modulus(x, p());
   }

BigInt Montgomery_Params::redc(const BigInt& x) const
   {
   const size_t output_size = 2*m_p_words + 2;
   std::vector<word> ws(output_size);
   BigInt z = x;
   z.grow_to(output_size);

   bigint_monty_redc(z.mutable_data(),
                     m_p.data(), m_p_words, m_p_dash,
                     ws.data(), ws.size());

   secure_scrub_memory(ws.data(), ws.size() * sizeof(word));
   return z;
   }

BigInt Montgomery_Params::mul(const BigInt& x, const BigInt& y) const
   {
   const size_t output_size = 2*m_p_words + 2;
   std::vector<word> ws(output_size);
   BigInt z(BigInt::Positive, output_size);
   bigint_mul(z.mutable_data(), z.size(),
              x.data(), x.size(), x.sig_words(),
              y.data(), y.size(), y.sig_words(),
              ws.data(), ws.size());

   bigint_monty_redc(z.mutable_data(),
                     m_p.data(), m_p_words, m_p_dash,
                     ws.data(), ws.size());

   secure_scrub_memory(ws.data(), ws.size() * sizeof(word));
   return z;
   }

BigInt Montgomery_Params::mul(const BigInt& x, const secure_vector<word>& y) const
   {
   const size_t output_size = 2*m_p_words + 2;
   std::vector<word> ws(output_size);
   BigInt z(BigInt::Positive, output_size);

   bigint_mul(z.mutable_data(), z.size(),
              x.data(), x.size(), x.sig_words(),
              y.data(), y.size(), y.size(),
              ws.data(), ws.size());

   bigint_monty_redc(z.mutable_data(),
                     m_p.data(), m_p_words, m_p_dash,
                     ws.data(), ws.size());

   secure_scrub_memory(ws.data(), ws.size() * sizeof(word));
   return z;
   }

BigInt Montgomery_Params::sqr(const BigInt& x) const
   {
   const size_t output_size = 2*m_p_words + 2;
   std::vector<word> ws(output_size);
   BigInt z(BigInt::Positive, output_size);

   bigint_sqr(z.mutable_data(), z.size(),
              x.data(), x.size(), x.sig_words(),
              ws.data(), ws.size());

   bigint_monty_redc(z.mutable_data(),
                     m_p.data(), m_p_words, m_p_dash,
                     ws.data(), ws.size());

   secure_scrub_memory(ws.data(), ws.size() * sizeof(word));
   return z;
   }

Montgomery_Int::Montgomery_Int(const std::shared_ptr<const Montgomery_Params> params,
                               const BigInt& v,
                               bool redc_needed) :
   m_params(params),
   m_v(redc_needed ? m_params->mul(v % m_params->p(), m_params->R2()) : v)
   {}

void Montgomery_Int::fix_size()
   {
   const size_t p_words = m_params->p_words();

   if(m_v.sig_words() > p_words)
      throw Internal_Error("Montgomery_Int::fix_size v too large");

   secure_vector<word>& w = m_v.get_word_vector();

   if(w.size() != p_words)
      {
      w.resize(p_words);
      w.shrink_to_fit();
      }
   }

bool Montgomery_Int::operator==(const Montgomery_Int& other) const
   {
   return m_v == other.m_v && m_params->p() == other.m_params->p();
   }

std::vector<uint8_t> Montgomery_Int::serialize() const
   {
   std::vector<uint8_t> v(size());
   BigInt::encode_1363(v.data(), v.size(), value());
   return v;
   }

size_t Montgomery_Int::size() const
   {
   return m_params->p().bytes();
   }

bool Montgomery_Int::is_one() const
   {
   return m_v == m_params->R1();
   }

bool Montgomery_Int::is_zero() const
   {
   return m_v.is_zero();
   }

BigInt Montgomery_Int::value() const
   {
   return m_params->redc(m_v);
   }

Montgomery_Int Montgomery_Int::operator+(const Montgomery_Int& other) const
   {
   BigInt z = m_v + other.m_v;
   secure_vector<word> ws;
   z.reduce_below(m_params->p(), ws);
   return Montgomery_Int(m_params, z, false);
   }

Montgomery_Int Montgomery_Int::operator-(const Montgomery_Int& other) const
   {
   BigInt z = m_v - other.m_v;
   if(z.is_negative())
      z += m_params->p();
   return Montgomery_Int(m_params, z, false);
   }

Montgomery_Int& Montgomery_Int::operator+=(const Montgomery_Int& other)
   {
   m_v += other.m_v;
   secure_vector<word> ws;
   m_v.reduce_below(m_params->p(), ws);
   return (*this);
   }

Montgomery_Int& Montgomery_Int::operator-=(const Montgomery_Int& other)
   {
   m_v -= other.m_v;
   if(m_v.is_negative())
      m_v += m_params->p();
   return (*this);
   }

Montgomery_Int Montgomery_Int::operator*(const Montgomery_Int& other) const
   {
   return Montgomery_Int(m_params, m_params->mul(m_v, other.m_v), false);
   }

Montgomery_Int& Montgomery_Int::operator*=(const Montgomery_Int& other)
   {
   m_v = m_params->mul(m_v, other.m_v);
   return (*this);
   }

Montgomery_Int& Montgomery_Int::operator*=(const secure_vector<word>& other)
   {
   m_v = m_params->mul(m_v, other);
   return (*this);
   }

Montgomery_Int& Montgomery_Int::square_this()
   {
   m_v = m_params->sqr(m_v);
   return (*this);
   }

Montgomery_Int Montgomery_Int::square() const
   {
   const BigInt v = m_params->sqr(m_v);
   return Montgomery_Int(m_params, v, false);
   }

Montgomery_Int Montgomery_Int::multiplicative_inverse() const
   {
   const BigInt iv = m_params->mul(m_params->inv_mod_p(m_v), m_params->R3());
   return Montgomery_Int(m_params, iv, false);
   }

Montgomery_Int Montgomery_Int::additive_inverse() const
   {
   return Montgomery_Int(m_params, m_params->p()) - (*this);
   }

Montgomery_Int& Montgomery_Int::mul_by_2(secure_vector<word>& ws)
   {
   m_v <<= 1;
   m_v.reduce_below(m_params->p(), ws);
   return (*this);
   }

Montgomery_Int& Montgomery_Int::mul_by_3(secure_vector<word>& ws)
   {
   m_v *= 3;
   m_v.reduce_below(m_params->p(), ws);
   return (*this);
   }

Montgomery_Int& Montgomery_Int::mul_by_4(secure_vector<word>& ws)
   {
   m_v <<= 2;
   m_v.reduce_below(m_params->p(), ws);
   return (*this);
   }

Montgomery_Int& Montgomery_Int::mul_by_8(secure_vector<word>& ws)
   {
   m_v <<= 3;
   m_v.reduce_below(m_params->p(), ws);
   return (*this);
   }

}

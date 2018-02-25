/*
* Montgomery Exponentiation
* (C) 1999-2010,2012,2018 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/monty_exp.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/internal/mp_core.h>

namespace Botan {

class Montgomery_Exponentation_State
   {
   public:
      Montgomery_Exponentation_State(const BigInt& g,
                                     const BigInt& p,
                                     const Modular_Reducer& mod_p,
                                     size_t window_bits);

      BigInt exponentiation(const BigInt& k) const;
   private:
      BigInt m_p;
      BigInt m_R_mod;
      BigInt m_R2_mod;
      word m_mod_prime;
      size_t m_p_words;
      size_t m_window_bits;
      std::vector<BigInt> m_g;
   };

Montgomery_Exponentation_State::Montgomery_Exponentation_State(const BigInt& g,
                                                               const BigInt& p,
                                                               const Modular_Reducer& mod_p,
                                                               size_t window_bits) :
   m_p(p),
   m_p_words(p.sig_words()),
   m_window_bits(window_bits)
   {
   if(p.is_positive() == false || p.is_even())
      throw Invalid_Argument("Cannot use Montgomery reduction on even or negative integer");

   if(window_bits > 12) // really even 8 is too large ...
      throw Invalid_Argument("Montgomery window bits too large");

   m_mod_prime = monty_inverse(m_p.word_at(0));

   const BigInt r = BigInt::power_of_2(m_p_words * BOTAN_MP_WORD_BITS);
   m_R_mod = mod_p.reduce(r);
   m_R2_mod = mod_p.square(m_R_mod);

   m_g.resize(1U << m_window_bits);

   BigInt z(BigInt::Positive, 2 * (m_p_words + 1));
   secure_vector<word> workspace(z.size());

   m_g[0] = 1;

   bigint_monty_mul(z, m_g[0], m_R2_mod,
                    m_p.data(), m_p_words, m_mod_prime,
                    workspace.data(), workspace.size());
   m_g[0] = z;

   m_g[1] = mod_p.reduce(g);

   bigint_monty_mul(z, m_g[1], m_R2_mod,
                    m_p.data(), m_p_words, m_mod_prime,
                    workspace.data(), workspace.size());

   m_g[1] = z;

   const BigInt& x = m_g[1];

   for(size_t i = 2; i != m_g.size(); ++i)
      {
      const BigInt& y = m_g[i-1];

      bigint_monty_mul(z, x, y, m_p.data(), m_p_words, m_mod_prime,
                       workspace.data(), workspace.size());

      m_g[i] = z;
      m_g[i].shrink_to_fit();
      m_g[i].grow_to(m_p_words);
      }
   }

BigInt Montgomery_Exponentation_State::exponentiation(const BigInt& k) const
   {
   const size_t exp_nibbles = (k.bits() + m_window_bits - 1) / m_window_bits;

   BigInt x = m_R_mod;

   const size_t z_size = 2*(m_p_words + 1);

   BigInt z(BigInt::Positive, z_size);
   secure_vector<word> workspace(z.size());
   secure_vector<word> e(m_p_words);

   for(size_t i = exp_nibbles; i > 0; --i)
      {
      for(size_t j = 0; j != m_window_bits; ++j)
         {
         bigint_monty_sqr(z, x, m_p.data(), m_p_words, m_mod_prime,
                          workspace.data(), workspace.size());

         x = z;
         }

      const uint32_t nibble = k.get_substring(m_window_bits*(i-1), m_window_bits);

      BigInt::const_time_lookup(e, m_g, nibble);

      bigint_mul(z.mutable_data(), z.size(),
                 x.data(), x.size(), x.sig_words(),
                 e.data(), m_p_words, m_p_words,
                 workspace.data(), workspace.size());

      bigint_monty_redc(z.mutable_data(),
                        m_p.data(), m_p_words, m_mod_prime,
                        workspace.data(), workspace.size());

      x = z;
      }

   x.grow_to(2*m_p_words + 1);

   bigint_monty_redc(x.mutable_data(),
                     m_p.data(), m_p_words, m_mod_prime,
                     workspace.data(), workspace.size());

   return x;
   }

std::shared_ptr<const Montgomery_Exponentation_State>
monty_precompute(const BigInt& g,
                 const BigInt& p,
                 const Modular_Reducer& mod_p,
                 size_t window_bits)
   {
   return std::make_shared<const Montgomery_Exponentation_State>(g, p, mod_p, window_bits);
   }

BigInt monty_execute(const Montgomery_Exponentation_State& precomputed_state,
                     const BigInt& k)
   {
   return precomputed_state.exponentiation(k);
   }

}


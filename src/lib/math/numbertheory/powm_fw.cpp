/*
* Fixed Window Exponentiation
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/def_powm.h>
#include <vector>

namespace Botan {

/*
* Set the exponent
*/
void Fixed_Window_Exponentiator::set_exponent(const BigInt& e)
   {
   m_exp = e;
   }

/*
* Set the base
*/
void Fixed_Window_Exponentiator::set_base(const BigInt& base)
   {
   m_window_bits = Power_Mod::window_bits(m_exp.bits(), base.bits(), m_hints);

   m_g.resize((1U << m_window_bits));
   m_g[0] = 1;
   m_g[1] = base;

   for(size_t i = 2; i != m_g.size(); ++i)
      m_g[i] = m_reducer.multiply(m_g[i-1], m_g[1]);
   }

/*
* Compute the result
*/
BigInt Fixed_Window_Exponentiator::execute() const
   {
   const size_t exp_nibbles = (m_exp.bits() + m_window_bits - 1) / m_window_bits;

   BigInt x = 1;

   for(size_t i = exp_nibbles; i > 0; --i)
      {
      for(size_t j = 0; j != m_window_bits; ++j)
         x = m_reducer.square(x);

      const uint32_t nibble = m_exp.get_substring(m_window_bits*(i-1), m_window_bits);

      x = m_reducer.multiply(x, m_g[nibble]);
      }
   return x;
   }

/*
* Fixed_Window_Exponentiator Constructor
*/
Fixed_Window_Exponentiator::Fixed_Window_Exponentiator(const BigInt& n,
                                                       Power_Mod::Usage_Hints hints)
      : m_reducer{Modular_Reducer(n)}, m_exp{}, m_window_bits{}, m_g{}, m_hints{hints}
   {}

}

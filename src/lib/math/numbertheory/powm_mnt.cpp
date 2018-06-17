/*
* Montgomery Exponentiation
* (C) 1999-2010,2012,2018 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/def_powm.h>
#include <botan/numthry.h>
#include <botan/monty.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/rounding.h>

namespace Botan {

void Montgomery_Exponentiator::set_exponent(const BigInt& exp)
   {
   m_e = exp;
   }

void Montgomery_Exponentiator::set_base(const BigInt& base)
   {
   size_t window_bits = Power_Mod::window_bits(m_e.bits(), base.bits(), m_hints);
   m_monty = monty_precompute(m_monty_params, base, window_bits);
   }

BigInt Montgomery_Exponentiator::execute() const
   {
   /*
   This leaks size of e via loop iterations, not possible to fix without
   breaking this API. Round up to avoid leaking fine details.
   */
   return monty_execute(*m_monty, m_e, round_up(m_e.bits(), 8));
   }

Montgomery_Exponentiator::Montgomery_Exponentiator(const BigInt& mod,
                                                   Power_Mod::Usage_Hints hints) :
   m_p(mod),
   m_mod_p(mod),
   m_monty_params(std::make_shared<Montgomery_Params>(m_p, m_mod_p)),
   m_hints(hints)
   {
   }

}

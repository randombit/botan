/*
* Fixed Window Exponentiation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/def_powm.h>
#include <botan/numthry.h>
#include <vector>

namespace Botan {

/*
* Set the exponent
*/
void Fixed_Window_Exponentiator::set_exponent(const BigInt& e)
   {
   exp = e;
   }

/*
* Set the base
*/
void Fixed_Window_Exponentiator::set_base(const BigInt& base)
   {
   window_bits = Power_Mod::window_bits(exp.bits(), base.bits(), hints);

   g.resize((1 << window_bits));
   g[0] = 1;
   g[1] = base;

   for(size_t i = 2; i != g.size(); ++i)
      g[i] = reducer.multiply(g[i-1], g[0]);
   }

/*
* Compute the result
*/
BigInt Fixed_Window_Exponentiator::execute() const
   {
   const size_t exp_nibbles = (exp.bits() + window_bits - 1) / window_bits;

   BigInt x = 1;

   for(size_t i = exp_nibbles; i > 0; --i)
      {
      for(size_t j = 0; j != window_bits; ++j)
         x = reducer.square(x);

      const u32bit nibble = exp.get_substring(window_bits*(i-1), window_bits);

      x = reducer.multiply(x, g[nibble]);
      }
   return x;
   }

/*
* Fixed_Window_Exponentiator Constructor
*/
Fixed_Window_Exponentiator::Fixed_Window_Exponentiator(const BigInt& n,
   Power_Mod::Usage_Hints hints)
   {
   reducer = Modular_Reducer(n);
   this->hints = hints;
   window_bits = 0;
   }

}

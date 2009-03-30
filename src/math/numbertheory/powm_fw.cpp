/*
* Fixed Window Exponentiation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/def_powm.h>
#include <botan/numthry.h>
#include <vector>

namespace Botan {

namespace {

/*
* Try to choose a good window size
*/
u32bit choose_window_bits(u32bit exp_bits, u32bit,
                          Power_Mod::Usage_Hints hints)
   {
   static const u32bit wsize[][2] = {
      { 2048, 7 }, { 1024, 6 }, { 256, 5 }, { 128, 4 }, { 64, 3 }, { 0, 0 }
   };

   u32bit window_bits = 3;

   if(exp_bits)
      {
      for(u32bit j = 0; wsize[j][0]; ++j)
         {
         if(exp_bits >= wsize[j][0])
            {
            window_bits += wsize[j][1];
            break;
            }
         }
      }

   if(hints & Power_Mod::EXP_IS_FIXED)
      window_bits += 2;
   if(hints & Power_Mod::EXP_IS_LARGE)
      window_bits += 2;
   if(hints & Power_Mod::BASE_IS_FIXED)
      ++window_bits;

   return window_bits;
   }

}

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
   window_bits = choose_window_bits(exp.bits(), base.bits(), hints);

   g.resize((1 << window_bits) - 1);
   g[0] = base;
   for(u32bit j = 1; j != g.size(); ++j)
      g[j] = reducer.multiply(g[j-1], g[0]);
   }

/*
* Compute the result
*/
BigInt Fixed_Window_Exponentiator::execute() const
   {
   const u32bit exp_nibbles = (exp.bits() + window_bits - 1) / window_bits;

   BigInt x = 1;
   for(u32bit j = exp_nibbles; j > 0; --j)
      {
      for(u32bit k = 0; k != window_bits; ++k)
         x = reducer.square(x);

      u32bit nibble = exp.get_substring(window_bits*(j-1), window_bits);
      if(nibble)
         x = reducer.multiply(x, g[nibble-1]);
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

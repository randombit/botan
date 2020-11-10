/*
* (C) 2007,2008 Falko Strenzke, FlexSecure GmbH
* (C) 2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/numthry.h>
#include <botan/reducer.h>

namespace Botan {

/*
* Tonelli-Shanks algorithm
*/
BigInt ressol(const BigInt& a, const BigInt& p)
   {
   if(p <= 1 || p.is_even())
      throw Invalid_Argument("ressol: invalid prime");

   if(a == 0)
      return 0;
   else if(a < 0)
      throw Invalid_Argument("ressol: value to solve for must be positive");
   else if(a >= p)
      throw Invalid_Argument("ressol: value to solve for must be less than p");

   if(p == 2)
      return a;

   if(jacobi(a, p) != 1) // not a quadratic residue
      return -BigInt(1);

   if(p % 4 == 3) // The easy case
      {
      return power_mod(a, ((p+1) >> 2), p);
      }

   size_t s = low_zero_bits(p - 1);
   BigInt q = p >> s;

   q -= 1;
   q >>= 1;

   Modular_Reducer mod_p(p);

   BigInt r = power_mod(a, q, p);
   BigInt n = mod_p.multiply(a, mod_p.square(r));
   r = mod_p.multiply(r, a);

   if(n == 1)
      return r;

   // find random quadratic nonresidue z
   word z = 2;
   for(;;)
      {
      if(jacobi(z, p) == -1) // found one
         break;

      z += 1; // try next z

      /*
      * The expected number of tests to find a non-residue modulo a
      * prime is 2. If we have not found one after 256 then almost
      * certainly we have been given a non-prime p.
      */
      if(z >= 256)
         return -BigInt(1);
      }

   BigInt c = power_mod(z, (q << 1) + 1, p);

   while(n > 1)
      {
      q = n;

      size_t i = 0;
      while(q != 1)
         {
         q = mod_p.square(q);
         ++i;

         if(i >= s)
            {
            return -BigInt(1);
            }
         }

      c = power_mod(c, BigInt::power_of_2(s-i-1), p);
      r = mod_p.multiply(r, c);
      c = mod_p.square(c);
      n = mod_p.multiply(n, c);
      s = i;
      }

   return r;
   }

}

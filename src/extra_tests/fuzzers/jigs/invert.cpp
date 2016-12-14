/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "driver.h"
#include <botan/numthry.h>

BigInt inverse_mod_ref(const BigInt& n, const BigInt& mod)
   {
   if(n == 0)
      return 0;

   BigInt u = mod, v = n;
   BigInt B = 0, D = 1;

   while(u.is_nonzero())
      {
      const size_t u_zero_bits = low_zero_bits(u);
      u >>= u_zero_bits;
      for(size_t i = 0; i != u_zero_bits; ++i)
         {
         //B.cond_sub(B.is_odd(), mod);
         if(B.is_odd())
            { B -= mod; }
         B >>= 1;
         }

      const size_t v_zero_bits = low_zero_bits(v);
      v >>= v_zero_bits;
      for(size_t i = 0; i != v_zero_bits; ++i)
         {
         if(D.is_odd())
            { D -= mod; }
         D >>= 1;
         }

      if(u >= v) { u -= v; B -= D; }
      else       { v -= u; D -= B; }
      }

   if(v != 1)
      return 0; // no modular inverse

   while(D.is_negative()) D += mod;
   while(D >= mod) D -= mod;

   return D;
   }


void fuzz(const uint8_t in[], size_t len)
   {
   if(len % 2 == 1 || len > 2*4096/8)
      return;

   const BigInt x = BigInt::decode(in, len / 2);
   BigInt mod = BigInt::decode(in + len / 2, len / 2);

   mod.set_bit(0);

   if(mod < 3 || x >= mod)
      return;

   BigInt ref = inverse_mod_ref(x, mod);
   BigInt ct = ct_inverse_mod_odd_modulus(x, mod);
   //BigInt mon = normalized_montgomery_inverse(x, mod);

   if(ref != ct)
      {
      std::cout << "X = " << x << "\n";
      std::cout << "P = " << mod << "\n";
      std::cout << "GCD = " << gcd(x, mod) << "\n";
      std::cout << "Ref = " << ref << "\n";
      std::cout << "CT  = " << ct << "\n";
      //std::cout << "Mon = " << mon << "\n";

      std::cout << "RefCheck = " << (ref*ref)%mod << "\n";
      std::cout << "CTCheck  = " << (ct*ct)%mod << "\n";
      //std::cout << "MonCheck = " << (mon*mon)%mod << "\n";
      abort();
      }
   }


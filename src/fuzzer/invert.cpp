/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"
#include <botan/numthry.h>

namespace {

Botan::BigInt ref_inverse_mod(const Botan::BigInt& n, const Botan::BigInt& mod)
   {
   if(n == 0 || mod < 2)
      return 0;
   if(n.is_even() && mod.is_even())
      return 0;
   Botan::BigInt u = mod, v = n;
   Botan::BigInt A = 1, B = 0, C = 0, D = 1;

   while(u.is_nonzero())
      {
      const size_t u_zero_bits = Botan::low_zero_bits(u);
      u >>= u_zero_bits;
      for(size_t i = 0; i != u_zero_bits; ++i)
         {
         if(A.is_odd() || B.is_odd())
            { A += n; B -= mod; }
         A >>= 1; B >>= 1;
         }

      const size_t v_zero_bits = Botan::low_zero_bits(v);
      v >>= v_zero_bits;
      for(size_t i = 0; i != v_zero_bits; ++i)
         {
         if(C.is_odd() || D.is_odd())
            { C += n; D -= mod; }
         C >>= 1; D >>= 1;
         }

      if(u >= v) { u -= v; A -= C; B -= D; }
      else       { v -= u; C -= A; D -= B; }
      }

   if(v != 1)
      return 0; // no modular inverse

   while(D.is_negative()) D += mod;
   while(D >= mod) D -= mod;

   return D;
   }

}

void fuzz(const uint8_t in[], size_t len)
   {
   if(len % 2 == 1 || len > 2*4096/8)
      return;

   const size_t part_len = len / 2;

   const Botan::BigInt x = Botan::BigInt::decode(in, part_len);
   Botan::BigInt mod = Botan::BigInt::decode(in + part_len, part_len);

   if(mod < 2)
      return;

   const Botan::BigInt ref = ref_inverse_mod(x, mod);
   const Botan::BigInt lib = Botan::inverse_mod(x, mod);

   if(ref != lib)
      {
      FUZZER_WRITE_AND_CRASH("X = " << x << "\n"
                             << "P = " << mod << "\n"
                             << "GCD = " << gcd(x, mod) << "\n"
                             << "Ref = " << ref << "\n"
                             << "Lib  = " << lib << "\n"
                             << "RefCheck = " << (x*ref)%mod << "\n"
                             << "LibCheck  = " << (x*lib)%mod << "\n");
      }
   }


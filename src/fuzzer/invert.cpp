/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"
#include <botan/numthry.h>

void fuzz(const uint8_t in[], size_t len)
   {
   if(len % 2 == 1 || len > 2*4096/8)
      return;

   const size_t part_len = len / 2;

   const Botan::BigInt x = Botan::BigInt::decode(in, part_len);
   Botan::BigInt mod = Botan::BigInt::decode(in + part_len, part_len);

   mod.set_bit(0);

   if(mod < 3 || x >= mod)
      return;

   const Botan::BigInt ref = Botan::inverse_euclid(x, mod);
   const Botan::BigInt ct = Botan::ct_inverse_mod_odd_modulus(x, mod);
   //Botan::BigInt mon = Botan::normalized_montgomery_inverse(x, mod);

   if(ref != ct)
      {
      FUZZER_WRITE_AND_CRASH("X = " << x << "\n"
                             << "P = " << mod << "\n"
                             << "GCD = " << gcd(x, mod) << "\n"
                             << "Ref = " << ref << "\n"
                             << "CT  = " << ct << "\n"
                             << "RefCheck = " << (ref*ref)%mod << "\n"
                             << "CTCheck  = " << (ct*ct)%mod << "\n");
      }
   }

